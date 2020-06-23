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
    try:
        for i in range(string_header.CipherTableSize):
            cipher_entry = CipherEntry()
            for f in fields(cipher_entry):
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
    except ValueError:
        return None  # We're just assuming the file is bogus
    return cipher_table


def file_to_text(file_path):
    file_hex = gf.get_hex_data(file_path)
    string_header = get_header(file_hex)
    if string_header:
        cipher_table = get_cipher_table(string_header, file_hex)
        if cipher_table is None:
            return None
        string = ''
        file_offset = 0
        for entry in cipher_table.Entries:
            entry_hex = file_hex[string_header.Offset*2 + file_offset*2: string_header.Offset*2 + file_offset*2 + entry.Length*2]
            # print(f'Using key {entry.Key} for offset range {hex(file_offset)} to {hex(file_offset + entry.Length)}')
            file_offset += entry.Length
            c = cipher([entry_hex[i:i+2] for i in range(0, len(entry_hex), 2)], entry.Key)
            string += convert_to_unicode(''.join(c))
            string += '\n'
        return string
    return None


# file_to_text('D:/D2_Datamining/Package Unpacker/output/0912/0912-0000191E.bin')
# file_to_text('D:/D2_Datamining/Package Unpacker/output/0912/0912-00001FE7.bin')

def automatic_folder_converter_all(pkg_dir):
    pkg_db.start_db_connection()
    with open(f'text_all/{pkg_dir[-5:-1]}_text.txt', 'w', encoding='utf-8') as f:
        f.write('')

    entries = {x: y for x, y in pkg_db.get_entries_from_table(pkg_dir[-5:-1], 'ID, RefID')}
    print(entries)
    for id, entry_name in enumerate(os.listdir(pkg_dir)):
        if entries[id] == '0x1A8A':
            print(f'Writing {os.listdir(pkg_dir)[id]} text strings')
            with open(f'text_all/{pkg_dir[-5:-1]}_text.txt', 'a', encoding='utf-8') as f:
                f.write(os.listdir(pkg_dir)[id] + '\n')
                to_write = file_to_text(pkg_dir + os.listdir(pkg_dir)[id])
                if to_write is None:
                    continue
                f.write(to_write)
                f.write('\n\n')


all_packages = os.listdir('output_all/')
for pkg in all_packages:
    if 'investment_globals_client_' in pkg:
        automatic_folder_converter_all(f'D:/D2_Datamining/Package Unpacker/output_all/{pkg}/')