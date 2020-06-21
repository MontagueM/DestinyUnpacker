import pkg_db
import os


def convert_to_unicode(text):
    replacements1 = {
        '42': 'a',
        '43': 'b',
        '44': 'c',
        '45': 'd',
        '46': 'e',
        '47': 'f',
        '48': 'g',
        '49': 'h',
        '4A': 'i',
        '4B': 'j',
        '4C': 'k',
        '4D': 'l',
        '4E': 'm',
        '4F': 'n',
        '50': 'o',
        '51': 'p',
        '52': 'q',
        '53': 'r',
        '54': 's',
        '55': 't',
        '56': 'u',
        '57': 'v',
        '58': 'w',
        '59': 'x',
        '5A': 'y',
        '5B': 'z',
        '22': 'A',
        '23': 'B',
        '24': 'C',
        '25': 'D',
        '26': 'E',
        '27': 'F',
        '28': 'G',
        '29': 'H',
        '2A': 'I',
        '2B': 'J',
        '2C': 'K',
        '2D': 'L',
        '2E': 'M',
        '2F': 'N',
        '30': 'O',
        '31': 'P',
        '32': 'Q',
        '33': 'R',
        '34': 'S',
        '35': 'T',
        '36': 'U',
        '37': 'V',
        '38': 'W',
        '39': 'X',
        '3A': 'Y',
        '3B': 'Z',
        '01': ' ',
        '0F': '.',
        '08': "'",
        '03': '"',
        '1B': ':',
        '0D': ',',
        '0E': '-',
        '20': '?',
        '09': '(',
        '0A': ')',
        '02': '!',
        '1C': ';',
        '07': '&',
        '11': '0',
        '12': '1',
        '13': '2',
        '14': '3',
        '15': '4',
        '16': '5',
        '17': '6',
        '18': '7',
        '19': '8',
        '1A': '9',

    }
    replacements2 = {
        'E1BFB5': '—',
        'E28087': '...',
        '0E13SK0E1': '-'
    }
    text = ''.join([replacements1.get(c, c) for c in text])
    for x, y in replacements2.items():
        text = text.replace(x, y)
    return text


def find_string(file_dir):
    t = open(file_dir, 'rb')
    file_hex = t.read().hex().upper()
    file_hex_split = [file_hex[i:i+2] for i in range(0, len(file_hex), 2)]

    starting_offset = -1
    end_offset = -1
    for offset in range(len(file_hex_split)):
        if len(file_hex) - offset < 8:
            continue
        if '00' not in file_hex_split[offset:offset + 16]:
            starting_offset = offset
            break
    for offset in range(starting_offset, len(file_hex_split)):
        if file_hex_split[offset:offset + 4] == ['BD', '9F', '80', '80']:
            end_offset = offset

    if starting_offset == -1 or end_offset == -1:
        print('Cannot find string data.')
        return ''

    string_data = [x for x in file_hex_split[starting_offset:end_offset] if x != '00']
    return convert_to_unicode(string_data)


def automatic_folder_converter(pkg_dir):
    """
    Converts .bin to text.
    TODO:
    - take in pkg directory
    - read from database
    - if file entry BEFORE refID (in id?) == 0x1A88 and current refID == 0x1A8A
        - find_string(file)
    - append to a file called the pkg name or whatever
    :return:
    """
    pkg_db.start_db_connection()
    # Clearing file
    with open(pkg_dir + f'{pkg_dir[-5:-1]}_text.txt', 'w') as f:
        f.write('')

    entries = {x: y for x, y in pkg_db.get_entries_from_table(pkg_dir[-5:-1], 'ID, RefID')}
    print(entries)
    for id, entry_name in enumerate(os.listdir(pkg_dir)):
        if id >= len(os.listdir(pkg_dir))-2:
            continue
        if entries[id] == '0x1A88':
            if entries[id+1] == '0x1A8A':
                print(f'Writing {os.listdir(pkg_dir)[id+1]} data')
                with open(pkg_dir + f'{pkg_dir[-5:-1]}_text.txt', 'a') as f:
                    f.write(os.listdir(pkg_dir)[id+1] + '\n')
                    to_write = find_string(pkg_dir + os.listdir(pkg_dir)[id+1]).replace('.', '.\n').replace('.\n"', '."')
                    f.write(to_write)
                    f.write('\n\n')


# automatic_folder_converter('D:/D2_Datamining/Package Unpacker/output/0966/')
