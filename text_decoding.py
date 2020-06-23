import pkg_db
import os
import binascii
import general_functions as gf


def convert_to_unicode(text):
    replacements = {
        'ÞÔ': '—',
        'E28087': '...',
        '0E13SK0E1': '-',
        'â»': 'ü'
    }
    text = text.replace('00', '')  # Removing NUL
    file_hex_split = [text[i:i+2] for i in range(0, len(text), 2)]
    u = u''.join([binascii.unhexlify(x).decode('latin1') for x in file_hex_split])
    # print(u)
    for x, y in replacements.items():
        u = u.replace(x, y)
    # print(u)
    return u


def cipher(file_hex_split):
    return [gf.fill_hex_with_zeros(hex(int(x, 16) + 0x1F)[2:], 2) for x in file_hex_split]


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
    c = cipher(string_data)
    u = convert_to_unicode(''.join(c))
    return u


def automatic_folder_converter_1a88(pkg_dir):
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
                print(f'Writing {os.listdir(pkg_dir)[id+1]} text strings')
                with open(pkg_dir + f'{pkg_dir[-5:-1]}_text.txt', 'a', encoding='utf-8') as f:
                    f.write(os.listdir(pkg_dir)[id+1] + '\n')
                    to_write = find_string(pkg_dir + os.listdir(pkg_dir)[id+1]).replace('.', '.\n').replace('.\n"', '."')
                    # print(to_write)
                    f.write(to_write)
                    f.write('\n\n')


def automatic_folder_converter_all(pkg_dir):
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
    with open(f'text_all/{pkg_dir[-5:-1]}_text.txt', 'w', encoding='utf-8') as f:
        f.write('')

    entries = {x: y for x, y in pkg_db.get_entries_from_table(pkg_dir[-5:-1], 'ID, RefID')}
    print(entries)
    for id, entry_name in enumerate(os.listdir(pkg_dir)):
        if entries[id] == '0x1A8A':
            print(f'Writing {os.listdir(pkg_dir)[id]} text strings')
            with open(f'text_all/{pkg_dir[-5:-1]}_text.txt', 'a', encoding='utf-8') as f:
                f.write(os.listdir(pkg_dir)[id] + '\n')
                to_write = find_string(pkg_dir + os.listdir(pkg_dir)[id]).replace('.', '.\n').replace('.\n"', '."')
                f.write(to_write)
                f.write('\n\n')


def detect_text_strings(pkg_dir):
    # if 'globals' not in pkg_dir:
    #     return
    file_1a8a_counter = 0
    print(pkg_dir)
    if '_en' in pkg_dir:
        package_id = pkg_dir[-7:-3]
    else:
        package_id = pkg_dir[-4:]
    entries = {x: y for x, y in pkg_db.get_entries_from_table(package_id, 'ID, RefID')}
    for id, entry_name in enumerate(os.listdir(pkg_dir)):
        # print(entry_name)
        if entries[id] == '0x1A8A':
            file_1a8a_counter += 1
    print(file_1a8a_counter)
# automatic_folder_converter('D:/D2_Datamining/Package Unpacker/output/0599/')


if __name__ == "__main__":
    pkg_db.start_db_connection()
    all_packages = os.listdir('output_all/')
    for pkg in all_packages:
        detect_text_strings('output_all/' + pkg)
    # all_packages = os.listdir('output_all/')
    # for pkg in all_packages:
    #     if 'investment_globals_client_' in pkg:
    #         automatic_folder_converter_all(f'D:/D2_Datamining/Package Unpacker/output_all/{pkg}/')
