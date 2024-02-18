# SPXD-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Dmitry Kozlyuk
import argparse
import ctypes

import elftools.elf.elffile
import elftools.elf.sections


class BTFHeader(ctypes.Structure):
    _fields_ = (
        ("magic", ctypes.c_uint16),
        ("version", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("hdr_len", ctypes.c_uint32),
        ("type_off", ctypes.c_uint32),
        ("type_len", ctypes.c_uint32),
        ("str_off", ctypes.c_uint32),
        ("str_len", ctypes.c_uint32),
    )


class BTFExtHeader(ctypes.Structure):
    _fields_ = (
        ("magic", ctypes.c_uint16),
        ("version", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("hdr_len", ctypes.c_uint32),
        ("func_info_off", ctypes.c_uint32),
        ("func_info_len", ctypes.c_uint32),
        ("line_info_off", ctypes.c_uint32),
        ("line_info_len", ctypes.c_uint32),
    )


class BTFExtInfoSec(ctypes.Structure):
    _fields_ = (
        ("sec_name_off", ctypes.c_uint32),
        ("num_infos", ctypes.c_uint32),
    )


class BTFLineInfo(ctypes.Structure):
    _fields_ = (
        ("insn_off", ctypes.c_uint32),
        ("file_name_off", ctypes.c_uint32),
        ("line_off", ctypes.c_uint32),
        ("line_col", ctypes.c_uint32),
    )


class Reader:
    def __init__(self, data, offset=0, size=None):
        size = size or len(data[offset:])
        self._data = data[offset : offset + size]

    def can_read(self, ctype):
        return len(self._data) >= ctypes.sizeof(ctype)

    def read(self, ctype, size=None):
        size = size or ctypes.sizeof(ctype)
        data = self._data
        self._data = self._data[size:]
        return ctype.from_buffer_copy(data)


def wipe(file, offset, size):
    file.seek(offset)
    file.write(b"\x00" * size)


def wipe_string(file, string_table, string_table_file_offset, start_offset):
    end_offset = string_table.find(b"\x00", start_offset)
    if end_offset > 0:
        wipe(file, string_table_file_offset + start_offset, end_offset - start_offset)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", metavar="FILE")
    args = parser.parse_args()

    with open(args.file, "rb+") as file:
        image = elftools.elf.elffile.ELFFile(file)

        btf_section = image.get_section_by_name(".BTF")
        if btf_section.compressed:
            raise Exception("compressed .BTF is not supported")
        btf_data = btf_section.data()

        btf_ext_section = image.get_section_by_name(".BTF.ext")
        btf_ext_data = btf_ext_section.data()

        btf_header = BTFHeader.from_buffer_copy(btf_data)
        string_table_section_offset = btf_header.hdr_len + btf_header.str_off
        string_table_file_offset = btf_section["sh_offset"] + string_table_section_offset
        string_table = btf_data[string_table_section_offset:]

        btf_ext_header = BTFExtHeader.from_buffer_copy(btf_ext_data)

        # Wipe source file names and code lines.
        reader = Reader(
            btf_ext_data,
            btf_ext_header.hdr_len + btf_ext_header.line_info_off,
            btf_ext_header.line_info_len,
        )
        line_info_size = reader.read(ctypes.c_uint32).value
        while reader.can_read(BTFExtInfoSec):
            section = reader.read(BTFExtInfoSec)
            for _ in range(section.num_infos):
                info = reader.read(BTFLineInfo, line_info_size)
                wipe_string(
                    file, string_table, string_table_file_offset, info.file_name_off
                )
                wipe_string(file, string_table, string_table_file_offset, info.line_off)

        # Wipe function and source line information
        wipe(
            file,
            btf_ext_section["sh_offset"]
            + btf_ext_header.hdr_len
            + btf_ext_header.func_info_off,
            btf_ext_header.func_info_len,
        )
        wipe(
            file,
            btf_ext_section["sh_offset"]
            + btf_ext_header.hdr_len
            + btf_ext_header.line_info_off,
            btf_ext_header.line_info_len,
        )

        # Truncate function and source line information.
        btf_ext_header.func_info_off = 0
        btf_ext_header.func_info_len = 0
        btf_ext_header.line_info_off = 0
        btf_ext_header.line_info_len = 0
        file.seek(btf_ext_section["sh_offset"])
        file.write(bytes(btf_ext_header))


if __name__ == "__main__":
    main()
