from dataclasses import dataclass, fields, field
import numpy as np
from typing import List
import pkg_db
# TODO Deal with this later too
import general_functions as gf
import os
from ctypes import cdll, c_char_p, create_string_buffer
from Crypto.Cipher import AES
import binascii


"""
Main program with every other file concatenated into a single file
"""


def get_file_typename(file_type, file_subtype):
    if file_type == 8:
        return '8080xxxx Structure File'
    elif file_type == 25:
        return 'OTF Font'
    elif file_type == 26:
        if file_subtype == 4 or file_subtype == 5:
            return 'BKHD'
        elif file_subtype == 6:
            return 'RIFF'
        elif file_subtype == 7:
            return 'Havok'
    elif file_type == 27:
        return 'USM Video'
    elif file_type == 32:
        if file_subtype == 1 or file_subtype == 2 or file_subtype == 3:
            return 'Texture Header'
        elif file_subtype == 4:
            return '12 byte Stride Header'
        elif file_subtype == 6:
            return '24 byte Faces Header'
        elif file_subtype == 7:
            return '16 byte Unknown Header'
    elif file_type == 33:
        return 'DirectX Bytecode Header'
    elif file_type == 40:
        if file_subtype == 1 or file_subtype == 2 or file_subtype == 3:
            return 'Texture Data'
        elif file_subtype == 4:
            return 'Stride Header'
        elif file_subtype == 6:
            return 'Faces Header'
        elif file_subtype == 7:
            return 'Unknown Data'
    elif file_type == 41:
        return 'DirectX Bytecode Data'
    elif file_type == 48:
        return 'Texture Header (UI)'
    else:
        return 'Unknown'


# All of these decoding functions use the information from formats.c on how to decode each entry
def decode_entry_a(entry_a_data):
    bin_a = int(bin(entry_a_data), 2)

    ref_id = bin_a & 0x1FFF
    ref_pkg_id = (bin_a >> 13) & 0x1FF
    ref_unk_id = (bin_a >> 22) & 0x3FFF
    # print(f'RefID: {ref_id} RefPackageID: {ref_pkg_id} RefUnkID: {ref_unk_id}')
    # print(f'RefID: {gf.fill_hex_with_zeros(hex(ref_id)[2:], 4)} RefPackageID: {gf.fill_hex_with_zeros(hex(ref_pkg_id)[2:], 4)}')
    return np.uint16(ref_id), np.uint16(ref_pkg_id), np.uint16(ref_unk_id)


def decode_entry_b(entry_b_data):
    bin_b = int(bin(entry_b_data), 2)

    file_subtype = (bin_b >> 6) & 0x7
    file_type = (bin_b >> 9) & 0x7F
    # print(f'Type: {file_type} SubType: {file_subtype}')
    return np.uint8(file_type), np.uint8(file_subtype)


def decode_entry_c(entry_c_data):
    bin_c = int(bin(entry_c_data), 2)

    starting_block = bin_c & 0x3FFF
    starting_block_offset = ((bin_c >> 14) & 0x3FFF) << 4

    # print(f'StartingBlock: {starting_block} StartingBlockOffset: {starting_block_offset}')
    # print(f'StartingBlock: {hex(starting_block)} StartingBlockOffset: {hex(starting_block_offset)}')
    return np.uint16(starting_block), np.uint32(starting_block_offset)


def decode_entry_d(entry_c_data, entry_d_data):
    bin_c = int(bin(entry_c_data), 2)
    bin_d = int(bin(entry_d_data), 2)

    file_size = (bin_d & 0x3FFFFFF) << 4 | (bin_c >> 28) & 0xF
    unknown = (bin_d >> 26) & 0x3F
    # print(f'FileSize: {file_size} Unknown: {unknown}')
    return np.uint32(file_size), np.uint8(unknown)


class OodleDecompressor:
    """
    Oodle decompression implementation.
    Requires Windows and the external Oodle library.
    """

    def __init__(self, library_path: str) -> None:
        """
        Initialize instance and try to load the library.
        """
        if not os.path.exists(library_path):
            raise Exception("Could not open Oodle DLL, make sure it is configured correctly.")

        try:
            self.handle = cdll.LoadLibrary(library_path)
        except OSError as e:
            raise Exception(
                "Could not load Oodle DLL, requires Windows and 64bit python to run."
            ) from e

    def decompress(self, payload: bytes) -> bytes:
        """
        Decompress the payload using the given size.
        """
        force_size = int('0x40000', 16)
        output = create_string_buffer(force_size)
        self.handle.OodleLZ_Decompress(
            c_char_p(payload), force_size, output, force_size,
            0, 0, 0, None, None, None, None, None, None, 3)

        return output.raw


@dataclass
class SPkgHeader:
    Version: np.uint16 = np.uint16(0)
    Platform: np.uint16 = np.uint16(0)
    PackageID: np.uint16 = np.uint16(0)
    Field6: np.uint16 = np.uint16(0)
    Field8: np.uint32 = np.uint32(0)
    FieldC: np.uint32 = np.uint32(0)
    Field10: np.uint32 = np.uint32(0)
    Field14: np.uint32 = np.uint32(0)
    Field18: np.uint32 = np.uint32(0)
    Field1C: np.uint32 = np.uint32(0)
    PatchID: np.uint16 = np.uint16(0)
    Field22: np.uint16 = np.uint16(0)
    BuildString: np.uint32 = np.uint32(0)
    Field28: np.uint32 = np.uint32(0)
    Field2C: np.uint32 = np.uint32(0)
    Field30: np.uint32 = np.uint32(0)
    Field34: np.uint32 = np.uint32(0)
    Field38: np.uint32 = np.uint32(0)
    Field3C: np.uint32 = np.uint32(0)
    Field40: np.uint32 = np.uint32(0)
    Field44: np.uint32 = np.uint32(0)
    Field48: np.uint32 = np.uint32(0)
    Field4C: np.uint32 = np.uint32(0)
    Field50: np.uint32 = np.uint32(0)
    Field54: np.uint32 = np.uint32(0)
    Field58: np.uint32 = np.uint32(0)
    Field5C: np.uint32 = np.uint32(0)
    Field60: np.uint32 = np.uint32(0)
    Field64: np.uint32 = np.uint32(0)
    Field68: np.uint32 = np.uint32(0)
    Field6C: np.uint32 = np.uint32(0)
    Field70: np.uint32 = np.uint32(0)
    Field74: np.uint32 = np.uint32(0)
    Field78: np.uint32 = np.uint32(0)
    Field7C: np.uint32 = np.uint32(0)
    Field80: np.uint32 = np.uint32(0)
    Field84: np.uint32 = np.uint32(0)
    Field88: np.uint32 = np.uint32(0)
    Field8C: np.uint32 = np.uint32(0)
    Field90: np.uint32 = np.uint32(0)
    Field94: np.uint32 = np.uint32(0)
    Field98: np.uint32 = np.uint32(0)
    Field9C: np.uint32 = np.uint32(0)
    FieldA0: np.uint32 = np.uint32(0)
    FieldA4: np.uint32 = np.uint32(0)
    FieldA8: np.uint32 = np.uint32(0)
    FieldAC: np.uint32 = np.uint32(0)
    SignatureOffset: np.uint32 = np.uint32(0)
    EntryTableSize: np.uint32 = np.uint32(0)  # The number of entries in the entry table
    FieldB8: np.uint32 = np.uint32(0)
    FieldBC: np.uint32 = np.uint32(0)
    FieldC0: np.uint32 = np.uint32(0)
    FieldC4: np.uint32 = np.uint32(0)
    FieldC8: np.uint32 = np.uint32(0)
    FieldCC: np.uint32 = np.uint32(0)
    BlockTableSize: np.uint32 = np.uint32(0)
    FieldD4: np.uint32 = np.uint32(0)
    FieldD8: np.uint32 = np.uint32(0)
    FieldDC: np.uint32 = np.uint32(0)
    FieldE0: np.uint32 = np.uint32(0)
    FieldE4: np.uint32 = np.uint32(0)
    FieldE8: np.uint32 = np.uint32(0)
    FieldEC: np.uint32 = np.uint32(0)
    UnkTableOffset: np.uint32 = np.uint32(0)
    UnkTableSize: np.uint32 = np.uint32(0)
    UnkTableHash: List[np.uint8] = field(default_factory=list)  # [0x14]
    UnkTableEntrySize: np.uint32 = np.uint32(0)
    EntryTableOffset: np.uint32 = np.uint32(0)
    EntryTableLength: np.uint32 = np.uint32(0)
    EntryTableHash: List[np.uint8] = field(default_factory=list)  # [0x14] so is actually a list of length 20
    BlockTableOffset: np.uint32 = np.uint32(0)
    Field130: np.uint32 = np.uint32(0)
    Field134: np.uint32 = np.uint32(0)
    Field138: np.uint32 = np.uint32(0)
    Field13C: np.uint32 = np.uint32(0)
    Field140: np.uint32 = np.uint32(0)
    Field144: np.uint32 = np.uint32(0)
    Field148: np.uint32 = np.uint32(0)
    Field14C: np.uint32 = np.uint32(0)
    Field150: np.uint32 = np.uint32(0)
    Field154: np.uint32 = np.uint32(0)
    Field158: np.uint32 = np.uint32(0)
    Field15C: np.uint32 = np.uint32(0)
    Field160: np.uint32 = np.uint32(0)
    Field164: np.uint32 = np.uint32(0)
    Field168: np.uint32 = np.uint32(0)
    Field16C: np.uint32 = np.uint32(0)


@dataclass
class SPkgEntry:
    EntryA: np.uint32 = np.uint32(0)
    EntryB: np.uint32 = np.uint32(0)
    EntryC: np.uint32 = np.uint32(0)
    EntryD: np.uint32 = np.uint32(0)


@dataclass
class SPkgEntryDecoded:
    ID: np.uint16 = np.uint16(0)
    FileName: str = ''
    FileType: str = ''
    RefID: np.uint16 = np.uint16(0)  # uint13
    RefPackageID: np.uint16 = np.uint16(0)  # uint9
    RefUnkID: np.uint16 = np.uint16(0)  # uint10
    Type: np.uint8 = np.uint8(0)  # uint7
    SubType: np.uint8 = np.uint8(0)  # uint3
    StartingBlock: np.uint16 = np.uint16(0)  # uint14
    StartingBlockOffset: np.uint32 = np.uint32(0)  # uint14
    FileSize: np.uint32 = np.uint32(0)  # uint30
    Unknown: np.uint8 = np.uint8(0)  # uint6


@dataclass
class SPkgEntryTable:
    Entries: List[SPkgEntryDecoded] = field(default_factory=list)  # This list of of length [EntryTableSize]


@dataclass
class SPkgBlockTableEntry:
    ID: int = 0
    Offset: np.uint32 = np.uint32(0)
    Size: np.uint32 = np.uint32(0)
    PatchID: np.uint16 = np.uint16(0)
    Flags: np.uint16 = np.uint16(0)
    Hash: List[np.uint8] = field(default_factory=list)  # [0x14] = 20
    GCMTag: List[np.uint8] = field(default_factory=list)  # [0x10] = 16


@dataclass
class SPkgBlockTable:
    Entries: List[SPkgBlockTableEntry] = field(default_factory=list)  # This list of length [BlockTableSize]


class Package:
    BLOCK_SIZE = int('0x40000', 16)

    AES_KEY_0 = [
        "0xD6", "0x2A", "0xB2", "0xC1", "0x0C", "0xC0",
        "0x1B", "0xC5", "0x35", "0xDB", "0x7B",
        "0x86", "0x55", "0xC7", "0xDC", "0x3B",
    ]
    AES_KEY_1 = [
        "0x3A", "0x4A", "0x5D", "0x36", "0x73", "0xA6",
        "0x60", "0x58", "0x7E", "0x63", "0xE6",
        "0x76", "0xE4", "0x08", "0x92", "0xB5",
    ]

    def __init__(self, package_directory):
        self.package_directory = package_directory
        # TODO Get max package here
        ###########
        self.package_id = self.package_directory[-10:-6]
        self.package_header = None
        self.entry_table = None
        self.block_table = None
        self.max_patch_id = self.package_directory[-5]
        self.max_pkg_hex = None

    def extract_package(self):
        print(f"Extracting files for {self.package_directory}")

        self.max_pkg_hex = gf.get_hex_data(self.package_directory)
        self.package_header = self.get_header()
        self.entry_table = self.get_entry_table()
        self.block_table = self.get_block_table()
        self.process_blocks()

        pkg_db.start_db_connection()
        pkg_db.drop_table(self.package_id)
        pkg_db.add_decoded_entries(self.entry_table.Entries, self.package_id)
        pkg_db.add_block_entries(self.block_table.Entries, self.package_id)

    def get_header(self):
        """
        Given a pkg directory, this gets the header data and uses SPkgHeader() struct to fill out the fields of that struct,
        making a header struct with all the correct data.
        :param pkg_dir:
        :return: the pkg header struct
        """
        header_length = int('0x16F', 16)
        # The header data is 0x16F bytes long, so we need to x2 as python reads each nibble not each byte
        header = self.max_pkg_hex[:header_length * 2]

        pkg_header = SPkgHeader()
        for f in fields(pkg_header):
            # How we add each data depends
            if f.type == np.uint32:
                flipped = "".join(gf.get_flipped_hex(header, 8))
                value = np.uint32(int(flipped, 16))
                setattr(pkg_header, f.name, value)
                header = header[8:]
            elif f.type == np.uint16:
                flipped = "".join(gf.get_flipped_hex(header, 4))
                value = np.uint16(int(flipped, 16))
                setattr(pkg_header, f.name, value)
                header = header[4:]
            elif f.type == np.uint8:
                flipped = "".join(gf.get_flipped_hex(header, 4))
                value = np.uint8(int(flipped, 16))
                setattr(pkg_header, f.name, value)
                header = header[2:]
            elif f.type == List[np.uint8]:
                # print(header)
                # these are 40 as the arrays need to be 20 long and uint8 so 40 bytes
                flipped = gf.get_flipped_hex(header, 40)
                # print(flipped)
                value = [np.uint8(int(flipped[i:i + 2], 16)) for i in range(len(flipped))]
                setattr(pkg_header, f.name, value)
                header = header[40:]
        return pkg_header

    def get_entry_table(self):
        """
        After we've got the header data for each pkg we know where the entry table is. Using this information, we take each
        row of 16 bytes (128 bits) as an entry and separate the row into EntryA, B, C, D for decoding
        :param pkg_data: the hex data from pkg
        :param entry_table_size: how long this entry table is in the pkg data
        :param entry_table_offset: hex offset for where the entry table starts
        :return: the entry table made
        """

        entry_table = SPkgEntryTable()
        entries_to_decode = []
        entry_table_start = self.package_header.EntryTableOffset*2
        entry_table_data = self.max_pkg_hex[entry_table_start:entry_table_start+self.package_header.EntryTableLength*2]

        for i in range(192, self.package_header.EntryTableSize * 32 + 192, 32):
            entry = SPkgEntry(np.uint32(int(gf.get_flipped_hex(entry_table_data[i:i + 8], 8), 16)),
                              np.uint32(int(gf.get_flipped_hex(entry_table_data[i + 8:i + 16], 8), 16)),
                              np.uint32(int(gf.get_flipped_hex(entry_table_data[i + 16:i + 24], 8), 16)),
                              np.uint32(int(gf.get_flipped_hex(entry_table_data[i + 24:i + 36], 8), 16)))
            entries_to_decode.append(entry)

        entry_table.Entries = self.decode_entries(entries_to_decode)
        return entry_table

    def decode_entries(self, entries_to_decode):
        """
        Given the entry table (and hence EntryA, B, C, D) we can decode each of them into data about each (file? block?)
        using bitwise operators.
        :param entry_table: the entry table struct to decode
        :return: array of decoded entries as struct SPkgEntryDecoded()
        """
        entries = []
        count = 0
        for entry in entries_to_decode:
            # print("\n\n")
            ref_id, ref_pkg_id, ref_unk_id = decode_entry_a(entry.EntryA)
            file_type, file_subtype = decode_entry_b(entry.EntryB)
            starting_block, starting_block_offset = decode_entry_c(entry.EntryC)
            file_size, unknown = decode_entry_d(entry.EntryC, entry.EntryD)
            file_name = f"{self.package_id}-{gf.fill_hex_with_zeros(hex(count)[2:], 8)}"
            file_typename = get_file_typename(file_type, file_subtype)

            decoded_entry = SPkgEntryDecoded(np.uint16(count), file_name, file_typename,
                                             ref_id, ref_pkg_id, ref_unk_id, file_type, file_subtype, starting_block,
                                             starting_block_offset, file_size, unknown)
            entries.append(decoded_entry)
            count += 1
        return entries

    def get_block_table(self):
        block_table_offset = self.package_header.EntryTableOffset + (self.package_header.EntryTableSize * 16) + 32 + 96
        block_table = SPkgBlockTable()
        block_table_data = self.max_pkg_hex[block_table_offset*2:block_table_offset*2 + self.package_header.BlockTableSize*48*2]
        reduced_bt_data = block_table_data
        for i in range(self.package_header.BlockTableSize):
            block_entry = SPkgBlockTableEntry(ID=i)
            for fd in fields(block_entry):
                if fd.type == np.uint32:
                    flipped = "".join(gf.get_flipped_hex(reduced_bt_data, 8))
                    value = np.uint32(int(flipped, 16))
                    setattr(block_entry, fd.name, value)
                    reduced_bt_data = reduced_bt_data[8:]
                elif fd.type == np.uint16:
                    flipped = "".join(gf.get_flipped_hex(reduced_bt_data, 4))
                    value = np.uint16(int(flipped, 16))
                    setattr(block_entry, fd.name, value)
                    reduced_bt_data = reduced_bt_data[4:]
                elif fd.type == List[np.uint8] and fd.name == 'Hash':
                    # these are 40 as the arrays need to be 20 long and uint8 so 40 bytes
                    flipped = gf.get_flipped_hex(reduced_bt_data, 40)
                    value = [np.uint8(int(flipped[i:i + 2], 16)) for i in range(len(flipped))]
                    setattr(block_entry, fd.name, value)
                    reduced_bt_data = reduced_bt_data[40:]
                elif fd.type == List[np.uint8] and fd.name == 'GCMTag':
                    # these are 32 as the arrays need to be 16 long and uint8 so 32 bytes
                    flipped = gf.get_flipped_hex(reduced_bt_data, 32)
                    value = [np.uint8(int(flipped[i:i + 2], 16)) for i in range(len(flipped))]
                    setattr(block_entry, fd.name, value)
                    reduced_bt_data = reduced_bt_data[32:]
            block_table.Entries.append(block_entry)
        return block_table

    def process_blocks(self):
        all_pkg_hex = []
        for i in range(int(self.max_patch_id) + 1):
            hex_data = gf.get_hex_data(f'{self.package_directory[:-6]}_{i}.pkg')
            all_pkg_hex.append(hex_data)

        blocks_bin = []
        for block in self.block_table.Entries:
            current_pkg_data = all_pkg_hex[block.PatchID]
            block_bin = binascii.unhexlify(current_pkg_data[block.Offset * 2:block.Offset * 2 + block.Size * 2])
            # We only decrypt/decompress if need to
            if block.Flags & 0x2:
                block_bin = self.decrypt_block(block, block_bin)
            if block.Flags & 0x1:
                block_bin = self.decompress_block(block_bin)
            blocks_bin.append(block_bin)

        self.output_files(blocks_bin)

    def decrypt_block(self, block, block_hex):
        aes_key_0 = binascii.unhexlify(''.join([x[2:] for x in self.AES_KEY_0]))
        aes_key_1 = binascii.unhexlify(''.join([x[2:] for x in self.AES_KEY_1]))

        nonce_seed = [
            0x84, 0xDF, 0x11, 0xC0,
            0xAC, 0xAB, 0xFA, 0x20,
            0x33, 0x11, 0x26, 0x99,
        ]

        nonce = nonce_seed
        package_id = int(f'0x{self.package_id}', 16)
        nonce[11] ^= package_id & 0xFF
        nonce[1] ^= 0x26
        nonce[0] ^= (package_id >> 8) & 0xFF
        nonce = binascii.unhexlify(''.join([hex(x)[2:] for x in nonce]))

        # gcm_tag = binascii.unhexlify(''.join([hex(x)[2:] for x in block_entry.GCMTag]))

        if block.Flags & 0x4:
            key = aes_key_1
        else:
            key = aes_key_0
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        # plaintext = cipher.decrypt_and_verify(hex_data, gcm_tag)  # Verification always gives a MAC check fail for some reason
        plaintext = cipher.decrypt(block_hex)
        return plaintext

    def decompress_block(self, block_bin):
        decompressor = OodleDecompressor('oo2core_3_win64.dll')
        decompressed = decompressor.decompress(block_bin)
        # print("Decompressed block")
        return decompressed

    def output_files(self, blocks_bin):
        try:
            os.mkdir('output/')
            os.mkdir('output/' + self.package_id)
        except FileExistsError:
            try:
                os.mkdir('output/' + self.package_id)
            except FileExistsError:
                pass

        for entry in self.entry_table.Entries:
            current_block = entry.StartingBlock
            block_offset = entry.StartingBlockOffset
            block_count = int(np.floor((block_offset + entry.FileSize - 1) / self.BLOCK_SIZE))
            last_block = current_block + block_count
            file_buffer = b''  # string of length entry.Size
            while current_block <= last_block:
                if current_block == entry.StartingBlock:
                    file_buffer = blocks_bin[current_block][block_offset:]
                else:
                    file_buffer += blocks_bin[current_block]
                current_block += 1
            with open(f'output/{self.package_id}/{entry.FileName.upper()}.bin', 'wb') as f:
                f.write(file_buffer[:entry.FileSize])
            print(f"Wrote to {entry.FileName} successfully\n")


pkg = Package("packages/w64_ui_01e3_6.pkg")
pkg.extract_package()
