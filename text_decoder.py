from dataclasses import dataclass, fields, field
import numpy as np
from typing import List
import pkg_db
import general_functions as gf
import os
import binascii


def convert_to_unicode(text):
    replacements = {
        'ÞÔ': '—',
        '0E13SK0E1': '-',
        'â»': 'ü',
        'ë¦': '...',
    }
    text = text.replace('00', '')  # Removing NUL
    file_hex_split = [text[i:i+2] for i in range(0, len(text), 2)]
    u = u''.join([binascii.unhexlify(x).decode('latin1') for x in file_hex_split])
    for x, y in replacements.items():
        u = u.replace(x, y)
    return u


def cipher(file_hex_split, key):
    return [gf.fill_hex_with_zeros(hex(int(x, 16) + key)[2:], 2) for x in file_hex_split]


@dataclass
class StringHeader:
    FileSize: np.uint32 = np.uint32(0)
    Field4: np.uint32 = np.uint32(0)
    Offset: np.uint32 = np.uint32(0)
    FieldC: np.uint32 = np.uint32(0)
    Field10: np.uint32 = np.uint32(0)
    Field14: np.uint32 = np.uint32(0)
    Field18: np.uint32 = np.uint32(0)
    Field1C: np.uint32 = np.uint32(0)
    Field20: np.uint32 = np.uint32(0)
    Field24: np.uint32 = np.uint32(0)
    Field28: np.uint32 = np.uint32(0)
    Field2C: np.uint32 = np.uint32(0)
    Field30: np.uint32 = np.uint32(0)
    Field34: np.uint32 = np.uint32(0)
    Length: np.uint32 = np.uint32(0)
    Field3C: np.uint32 = np.uint32(0)
    Field40: np.uint32 = np.uint32(0)
    Field44: np.uint32 = np.uint32(0)
    CipherTableSize: np.uint32 = np.uint32(0)
    Field4C: np.uint32 = np.uint32(0)
    Field50: np.uint32 = np.uint32(0)
    Field54: np.uint32 = np.uint32(0)
    Field58: np.uint32 = np.uint32(0)
    Field5C: np.uint32 = np.uint32(0)


@dataclass
class CipherEntry:
    Field0: np.uint32 = np.uint32(0)
    Field4: np.uint32 = np.uint16(0)
    Field8: np.uint32 = np.uint32(0)
    FieldC: np.uint32 = np.uint32(0)
    Field10: np.uint32 = np.uint32(0)
    Length: np.uint16 = np.uint16(0)  # 12
    Field14: np.uint16 = np.uint16(0)  # usually similar to length
    Key: np.uint16 = np.uint16(0)  # 16
    Field18: np.uint16 = np.uint16(0)
    Field1C: np.uint32 = np.uint32(0)


@dataclass
class CipherTable:
    Entries: List[CipherEntry] = field(default_factory=list)


def get_header(file_hex):
    header_length = int('0x60', 16)
    header = file_hex[:header_length * 2]

    str_header = StringHeader()
    for f in fields(str_header):
        if f.name == 'Offset' and f.type == np.uint32:
            flipped = "".join(gf.get_flipped_hex(header, 8))
            value = np.uint32(int(flipped, 16)) * 32 + 176  # The offset calculation
            setattr(str_header, f.name, value)
            header = header[8:]
        elif f.type == np.uint32:
            flipped = "".join(gf.get_flipped_hex(header, 8))
            value = np.uint32(int(flipped, 16))
            setattr(str_header, f.name, value)
            header = header[8:]
        elif f.type == np.uint16:
            flipped = "".join(gf.get_flipped_hex(header, 4))
            value = np.uint16(int(flipped, 16))
            setattr(str_header, f.name, value)
            header = header[4:]

    if str_header.Length < 16:
        return None
    return str_header


def get_cipher_table(string_header, file_hex):
    cipher_table = CipherTable()
    cipher_table_start = int('0x60', 16) + 16
    cipher_table_length = string_header.CipherTableSize * 32  # each cipher entry is 32 bytes long
    cipher_table_hex = file_hex[cipher_table_start*2:cipher_table_start*2 + cipher_table_length*2]
    print(cipher_table_hex[:64])
    for i in range(string_header.CipherTableSize):
        cipher_entry = CipherEntry()
        for f in fields(cipher_entry):
            print(cipher_table_hex, f.name)
            if f.type == np.uint32:
                flipped = "".join(gf.get_flipped_hex(cipher_table_hex, 8))
                value = np.uint32(int(flipped, 16))
                setattr(cipher_entry, f.name, value)
                cipher_table_hex = cipher_table_hex[8:]
            elif f.type == np.uint16:
                flipped = "".join(gf.get_flipped_hex(cipher_table_hex, 4))
                value = np.uint16(int(flipped, 16))
                setattr(cipher_entry, f.name, value)
                cipher_table_hex = cipher_table_hex[4:]
        cipher_table.Entries.append(cipher_entry)
    return cipher_table


def file_to_text(file_path):
    file_hex = gf.get_hex_data(file_path)
    string_header = get_header(file_hex)
    if string_header:
        cipher_table = get_cipher_table(string_header, file_hex)
        print(cipher_table.Entries)
        string = ''
        file_offset = 0
        for entry in cipher_table.Entries:
            entry_hex = file_hex[string_header.Offset*2 + file_offset*2: string_header.Offset*2 + file_offset*2 + entry.Length*2]
            print(f'Using key {entry.Key} for offset range {hex(file_offset)} to {hex(file_offset + entry.Length)}')
            file_offset += entry.Length
            c = cipher([entry_hex[i:i+2] for i in range(0, len(entry_hex), 2)], entry.Key)
            string += convert_to_unicode(''.join(c))
            string += '\n'
        print(string)
        # string_hex = file_hex[header.Offset*2:header.Offset*2 + header.Length*2]
        # print(string_hex)

        # print(u)


file_to_text('D:/D2_Datamining/Package Unpacker/output/0912/0912-0000191E.bin')
# file_to_text('D:/D2_Datamining/Package Unpacker/output/0912/0912-00001FE7.bin')

# string_hex = '03 2A 01 4B 56 54 55 01 4D 4A 4C 46 01 55 49 46 01 4F 42 4E 46 0F 01 25 50 46 54 4F 08 55 01 4E 46 42 4F 01 42 4F 5A 55 49 4A 4F 48 0F 03 01 E1 BF B5 2D 50 53 45 01 27 46 4D 58 4A 4F 55 46 53 01 55 50 01 2D 50 53 45 01 35 4A 4E 56 53 27 46 4D 58 4A 4F 55 46 53 08 54 01 2D'
# c = cipher(string_hex.split(' '))
# u = convert_to_unicode(''.join(c))
# print(u)
