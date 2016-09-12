#!/usr/bin/env python

"""asldump.py: Display the specified ASL files to standard output."""

import argparse
import datetime
import encodings.hex_codec
import itertools
import logging
import mmap
import os
import struct

__author__ = "Igor Mironov"
__copyright__ = "Copyright 2016, Igor Mironov"
__license__ = "Apache v2.0"

ASL_FILE_SIGNATURE = 0x41534c2044420000  # 'ASL DB\000\000'

FILE_HEADER_SIZE = 0x50
FILE_HEADER_UNK0 = '\000' * 7 + '\002'     # at 0x8
FILE_HEADER_UNK1 = '\000\000\001\000\000'  # at 0x20
FILE_HEADER_UNK2 = '\000' * 35             # at 0x2d

BLOCK_HEADER_SIZE = 6  # block type (2 bytes) and size (4 bytes)
NULL_BLOCK_OFFSET = 0  # a block offset used to indicate the absence of a block

RECORD_BLOCK_TYPE = 0
RECORD_HEADER_SIZE = 0x3c
RECORD_ITEM_SIZE = 8
RECORD_BLOCK_MIN_SIZE = RECORD_HEADER_SIZE + RECORD_ITEM_SIZE  # link to prev

STRING_BLOCK_TYPE = 1
STRING_BLOCK_MIN_SIZE = 1  # empty string with the NUL terminating character

StdOut, Debug, Info, Warn, Error = range(5)  # console output selectors


class ASLFile(object):

    def __init__(self, header, blocks, block_map):
        self.header = header
        self.blocks = blocks
        self.block_map = block_map


class ASLHeader(object):

    def __init__(self, signature, unknown0, first_record, timestamp, unknown1,
                 last_record, unknown2):
        self.signature = signature
        self.unknown0 = unknown0
        self.first_record = first_record
        self.timestamp = timestamp
        self.unknown1 = unknown1
        self.last_record = last_record
        self.unknown2 = unknown2


class ASLBlock(object):

    def __init__(self, offset, block_type, string, record, data):
        self.offset = offset
        self.block_type = block_type
        self.string = string
        self.record = record
        self.data = data


class ASLPrinter(object):

    def __init__(self, asl_file, console):
        self.asl_file = asl_file
        self.console = console
        self.visited_blocks = {NULL_BLOCK_OFFSET}
        self.visited_records = {NULL_BLOCK_OFFSET}

    def dump(self):
        console = self.console
        # display the file header information
        dump_header(self.asl_file.header, console)
        # display the record list starting with the first record
        visited_blocks = self.visited_blocks
        visited_records = self.visited_records
        first_record = self.asl_file.header.first_record
        if not first_record:
            console(Warn, 'The location of the first record is not specified')
        else:
            prev_block_offset = NULL_BLOCK_OFFSET
            block_offset = first_record
            self.dump_record_list(block_offset, prev_block_offset)
        # display the remaining records (they were not part of the record list)
        for block in self.asl_file.blocks:
            if block.record and block.offset not in visited_records:
                console(Warn, 'Unreferenced record %d', block.offset)
                self.dump_record_list(block.offset, -1)
        # display any other remaining blocks (strings and unparsed data)
        for block in self.asl_file.blocks:
            if block.offset not in visited_blocks:
                console(Warn, 'Unreferenced block %d', block.offset)
                self.dump_record(block.offset, None)

    def dump_record_list(self, block_offset, prev_block_offset):
        console = self.console
        visited_blocks = self.visited_blocks
        visited_records = self.visited_records
        while True:
            next_block_offset = self.dump_record(block_offset,
                                                 prev_block_offset)
            last_record = self.asl_file.header.last_record
            if not next_block_offset:
                if block_offset != last_record:
                    console(Warn, 'The location of the last record'
                            ' is incorrect (expected, %d, actual %d)',
                            last_record, block_offset)
                break
            if block_offset == last_record:
                console(Warn, 'The last record %d'
                        ' has a nonzero next record pointer (%d)',
                        block_offset, next_block_offset)
            prev_block_offset = block_offset
            block_offset = next_block_offset

    def dump_record(self, block_offset, prev_block_offset):
        console = self.console
        visited_blocks = self.visited_blocks
        visited_records = self.visited_records
        if block_offset in visited_records:
            if prev_block_offset:
                console(Error, ('Record %d referenced by record %d'
                                ' has already been processed'),
                        block_offset, prev_block_offset)
            else:
                console(Error, ('The first record %d'
                                ' has already been processed'),
                        block_offset)
            return NULL_BLOCK_OFFSET
        block = self.asl_file.block_map[block_offset]
        if not block:
            if prev_block_offset:
                console(Error, ('Couldn\'t find record %d'
                                ' referenced by record %d'),
                        block_offset, prev_block_offset)
            else:
                console(Error, 'Couldn\'t find the first record %d',
                        block_offset)
            return NULL_BLOCK_OFFSET
        visited_blocks.add(block_offset)  # mark this block as 'seen'
        record = block.record
        if not record:
            if prev_block_offset:
                console(Error, ('Record %d referenced by record %d'
                                ' contains invalid data'),
                        block_offset, prev_block_offset)
            elif prev_block_offset == NULL_BLOCK_OFFSET:
                console(Error, ('The first record %d'
                                ' contains invalid data'),
                        block_offset)
            if block.string:
                console(StdOut, "%d string: %s", block_offset, block.string)
            else:
                console(StdOut, "%d unparsed: %s", block_offset,
                        hex_encode(block.data))
            return NULL_BLOCK_OFFSET  # no 'next' pointer in string or raw data
        visited_records.add(block_offset)  # mark this record block as 'seen'
        items = record['ITEMS']
        pos_items = [self.lookup_item(i) for i in items[0:4]]   # positional
        map_items = [self.lookup_item(i) for i in items[6:-1]]  # key-value
        it = iter(map_items)
        string_map = dict(itertools.izip(it, it))
        console(StdOut, "%d record %d %s UTC %09d ns %s, %s, %s", block_offset,
                record['ID'], timestr(record['TIMESTAMP']),
                record['TIMESTAMP_NANOS'], record['UNKNOWN'], pos_items,
                string_map)
        next_record = record['NEXT']
        prev_record = items[-1]
        if prev_record != prev_block_offset:
            if prev_block_offset:
                console(Error, ('Previous record pointer in record %d'
                                ' is incorrect (expected %d, actual %d)'),
                        block_offset, prev_block_offset, prev_record)
            elif prev_block_offset == NULL_BLOCK_OFFSET:
                console(Error, ('Previous record pointer'
                                ' in the first record %d'
                                ' is incorrect (expected %d, actual %d)'),
                        block_offset, prev_block_offset, prev_record)
        return next_record

    def lookup_item(self, item):
        if isinstance(item, basestring):
            return item
        if not item:
            return None
        block = self.asl_file.block_map[item]
        if not block:
            return None
        self.visited_blocks.add(item)
        if block.string:
            return block.string
        if block.data:
            return block.data
        return "[asldump: pointer to record %d]" % item


def dump_file(file_name, console):
    st = os.stat(file_name)
    # Windows cannot mmap empty files so check this case separately
    if not st.st_size:
        console(Error, 'Empty file: %s', file_name)
        return
    with open(file_name, mode='rb') as in_file:
        asl_mmap = mmap.mmap(in_file.fileno(), 0, access=mmap.ACCESS_READ)
        asl_file = parse_file(file_name, asl_mmap, console)
        asl_mmap.close()
    if asl_file:
        ASLPrinter(asl_file, console).dump()


def dump_header(header, console):
    console(Info, 'Creation timestamp: %s UTC', timestr(header.timestamp))
    console(Info, 'Location of the first record: %d', header.first_record)
    console(Info, 'Location of the last record: %d', header.last_record)
    if header.unknown0 != FILE_HEADER_UNK0:
        console(Warn, 'File header unknown0: %s',
                hex_encode(header.unknown0))
    if header.unknown1 != FILE_HEADER_UNK1:
        console(Warn, 'File header unknown1: %s',
                hex_encode(header.unknown1))
    if header.unknown2 != FILE_HEADER_UNK2:
        console(Warn, 'File header unknown2: %s',
                hex_encode(header.unknown2))


def parse_file(file_name, file_data, console):
    console(Info, 'Input file:   %s', file_name)
    # see if the file has at least as many bytes as the ASL file header
    file_size = file_data.size()
    if file_size < FILE_HEADER_SIZE:
        console(Error, 'File is too short (%d bytes)', file_size)
        return None
    # parse the ASL file header
    file_header = file_data[0:FILE_HEADER_SIZE]
    (signature, unknown0, first_record, timestamp, unknown1, last_record,
     unknown2) = struct.unpack('>Q8sQQ5sQ35s', file_header)
    if signature != ASL_FILE_SIGNATURE:
        console(Error, 'Invalid file signature: %#x', signature)
        return None
    header = ASLHeader(signature, unknown0, first_record, timestamp, unknown1,
                       last_record, unknown2)
    blocks = []
    block_map = {}
    block_offset = FILE_HEADER_SIZE
    while block_offset < file_size:
        data_offset = block_offset + BLOCK_HEADER_SIZE
        block_header = file_data[block_offset:data_offset]
        block_type, block_size = struct.unpack('>HI', block_header)
        block_end = data_offset + block_size
        if file_size < block_end:
            console(Error, 'Block %d has invalid size (%d bytes)',
                    block_offset, block_size)
            # keep going with reduced block size
            block_size = file_size - data_offset
            block_end = file_size
        block_data = file_data[data_offset:block_end]
        block = parse_block(block_offset, block_type, block_size,
                            block_data, console)
        blocks.append(block)
        block_map[block_offset] = block
        block_offset = block_end
    console(Debug, 'Data blocks:  %s', blocks)
    return ASLFile(header, blocks, block_map)


def parse_block(block_offset, block_type, block_size, block_data, console):
    console(Debug, 'Block %d has type %d and size %d bytes',
            block_offset, block_type, block_size)
    string = None
    record = None
    if block_type == STRING_BLOCK_TYPE:
        if block_size < STRING_BLOCK_MIN_SIZE:
            console(Error, ('String block %d'
                            ' has invalid size (%d bytes)'),
                    block_offset, block_size)
            string_length = block_size
        else:
            string_length = block_size - 1
            strings = block_data.split('\000')
            if len(strings) != 2 or len(strings[0]) != string_length:
                console(Warn, ('String block %d'
                               ' is not correctly terminated'),
                        block_offset)
                # if the string is incorrectly terminated (the NUL character
                # appears in the middle or is omitted), then use the entire
                # block so that the user can see all data
                string_length = block_size
        string = block_data[0:string_length]
        # return string
    elif block_type == RECORD_BLOCK_TYPE:
        if block_size < STRING_BLOCK_MIN_SIZE:
            console(Error, ('Record block %d'
                            ' has invalid size (%d bytes)'),
                    block_offset, block_size)
            # return block_data
        else:
            record_header = block_data[0:RECORD_HEADER_SIZE]
            (next_record, record_id, timestamp, nanos, unk0, unk1, unk2, unk3,
             unk4, unk5, unk6, unk7) = struct.unpack('>3QI8i', record_header)
            unknown = [unk0, unk1, unk2, unk3, unk4, unk5, unk6, unk7]
            record_size = block_size - RECORD_HEADER_SIZE
            size_mismatch = record_size % RECORD_ITEM_SIZE
            if size_mismatch != 0:
                console(Error, ('Record block %d'
                                ' has invalid size (extra %d bytes)'),
                        block_offset, size_mismatch)
            item_offset = RECORD_HEADER_SIZE
            item_count = record_size // RECORD_ITEM_SIZE
            items = []
            for i in range(item_count):
                item_end = item_offset + RECORD_ITEM_SIZE
                item_data = block_data[item_offset:item_end]
                item_flag = ord(item_data[0])
                if item_flag >= 128:
                    item_length = item_flag & 127
                    if item_length > 7:
                        console(Error, ('Record item at offset %d'
                                        ' has invalid size (%d bytes)'),
                                item_offset, item_length)
                    item = item_data[1:1+item_length]
                else:
                    item = struct.unpack('>Q', item_data)[0]
                items.append(item)
                item_offset = item_end
            record = {'NEXT': next_record, 'ID': record_id,
                      'TIMESTAMP': timestamp, 'TIMESTAMP_NANOS': nanos,
                      'UNKNOWN': unknown, 'ITEMS': items}
            # return record
    else:
        console(Error, 'Block %d has invalid type (%d)',
                block_offset, block_type)
        # return block_data
    return ASLBlock(block_offset, block_type, string, record, block_data)


def print_message(level, message, *args):
    if level == StdOut:
        print message % args
    elif level == Debug:
        log.debug(message, *args)
    elif level == Info:
        log.info(message, *args)
    elif level == Warn:
        log.warn(message, *args)
    else:
        log.error(message, *args)


def timestr(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp)


def hex_encode(data):
    return encodings.hex_codec.hex_encode(data)[0]


def main(argv):
    for file_name in argv:
        dump_file(file_name, print_message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Display the specified ASL'
                                     ' files to standard output.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='add file header information')
    parser.add_argument('files', nargs='+', metavar='FILE',
                        help='input file(s)')
    args = parser.parse_args()
    logging_level = logging.INFO if args.verbose else logging.WARN
    logging.basicConfig(level=logging_level)
    log = logging.getLogger('asldump')
    main(args.files)
