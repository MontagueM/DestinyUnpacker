import sqlite3 as sq
import general_functions as gf

con = None
c = None


def start_db_connection():
    global con
    global c
    con = sq.connect('pkg_data.db')
    c = con.cursor()


def drop_table(pkg_id_to_drop):
    global c
    c.execute('DROP TABLE IF EXISTS _' + pkg_id_to_drop + '_DecodedData')
    c.execute('DROP TABLE IF EXISTS _' + pkg_id_to_drop + '_DecodedData_FullData')
    c.execute('DROP TABLE IF EXISTS _' + pkg_id_to_drop + '_BlockEntries')


def add_decoded_entries(decoded_entries, pkg_id):
    global con
    global c
    entries = [(int(decoded_entry.ID), decoded_entry.FileName.upper(),
               "0x" + gf.fill_hex_with_zeros(hex(decoded_entry.RefID)[2:], 4).upper(),
               "0x" + gf.fill_hex_with_zeros(hex(decoded_entry.RefPackageID)[2:], 4).upper(),
               int(decoded_entry.FileSize), int(decoded_entry.FileSize/1024),
               int(decoded_entry.Type), int(decoded_entry.SubType), decoded_entry.FileType) for decoded_entry in decoded_entries]
    c.execute('CREATE TABLE IF NOT EXISTS _' + pkg_id + '_DecodedData (ID INTEGER, FileName STRING, RefID STRING, RefPKG STRING, FileSizeB INTEGER, FileSizeKB INTEGER, Type INTEGER, SubType INTEGER, FileType STRING)')
    c.executemany('INSERT INTO _' + pkg_id + '_DecodedData (ID, FileName, RefID, RefPKG, FileSizeB, FileSizeKB, Type, SubType, FileType) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);',
              entries)

    entries_fulldata = [(int(decoded_entry.ID), decoded_entry.FileName.upper(),
               "0x" + gf.fill_hex_with_zeros(hex(decoded_entry.RefID)[2:], 4).upper(),
               "0x" + gf.fill_hex_with_zeros(hex(decoded_entry.RefPackageID)[2:], 4).upper(),
               int(decoded_entry.FileSize), int(decoded_entry.FileSize/1024),
               int(decoded_entry.Type), int(decoded_entry.SubType), decoded_entry.FileType,
                "0x" + gf.fill_hex_with_zeros(hex(decoded_entry.RefUnkID)[2:], 4).upper(),
                "0x" + gf.fill_hex_with_zeros(hex(decoded_entry.StartingBlock)[2:], 4).upper(),
                "0x" + gf.fill_hex_with_zeros(hex(decoded_entry.StartingBlockOffset)[2:], 8).upper()) for decoded_entry in decoded_entries]
    c.execute('CREATE TABLE IF NOT EXISTS _' + pkg_id + '_DecodedData_FullData (ID INTEGER, FileName STRING, RefID STRING, RefPKG STRING, FileSizeB INTEGER, FileSizeKB INTEGER, Type INTEGER, SubType INTEGER, FileType STRING, RefUnkID STRING, StartingBlock STRING, StartingBlockOffset STRING)')
    c.executemany('INSERT INTO _' + pkg_id + '_DecodedData_FullData (ID, FileName, RefID, RefPKG, FileSizeB, FileSizeKB, Type, SubType, FileType, RefUnkID, StartingBlock, StartingBlockOffset) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);',
              entries_fulldata)
    con.commit()
    print(f"Added {len(decoded_entries)} decoded entries to db")


def add_block_entries(block_entries, pkg_id):
    global con
    global c
    entries = [(int(entry.ID),
                "0x" + gf.fill_hex_with_zeros(hex(entry.Offset)[2:], 8).upper(),
                "0x" + gf.fill_hex_with_zeros(hex(entry.Size)[2:], 8).upper(),
                int(entry.Size), int(entry.PatchID), int(entry.Flags)) for entry in block_entries]
    c.execute('CREATE TABLE IF NOT EXISTS _' + pkg_id + '_BlockEntries (ID INTEGER, Offset STRING, Size STRING, SizeB INTEGER, PatchID INTEGER, Flags INTEGER)')
    c.executemany('INSERT INTO _' + pkg_id + '_BlockEntries (ID, Offset, Size, SizeB, PatchID, Flags) VALUES(?, ?, ?, ?, ?, ?);',
              entries)

    con.commit()
    print(f"Added {len(block_entries)} block entries to db")


def get_entries_from_table(pkg_id, column_select='*'):
    global c
    c.execute("SELECT " + column_select + " from _" + pkg_id + "_DecodedData")
    rows = c.fetchall()
    return rows
