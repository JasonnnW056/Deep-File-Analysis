"""Builds a tiny, valid 32-bit PE in memory so tests run on any OS (no real exe needed)."""
import struct


def build_minimal_pe(section_name=b".text", section_data=b"\x90" * 512,
                     characteristics=0x60000020, timestamp=0x5F000000, overlay=b""):
    file_align, sect_align, headers_size = 0x200, 0x1000, 0x200
    raw_size = (len(section_data) + file_align - 1) // file_align * file_align
    data = section_data.ljust(raw_size, b"\x00")

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH", 0x14C, 1, timestamp, 0, 0, 224, 0x0102)

    opt = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "HH" + "I" * 6,
        0x10B, 1, 0,
        raw_size, 0, 0, sect_align, sect_align, 0, 0x400000, sect_align, file_align,
        4, 0, 0, 0, 4, 0,
        0, sect_align * 2, headers_size, 0,
        3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"\x00" * (16 * 8)

    sect = struct.pack("<8sIIIIIIHHI", section_name.ljust(8, b"\x00"),
                       len(section_data), sect_align, raw_size, headers_size,
                       0, 0, 0, 0, characteristics)

    header = (bytes(dos) + b"PE\x00\x00" + coff + opt + sect).ljust(headers_size, b"\x00")
    return header + data + overlay