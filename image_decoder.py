from dataclasses import dataclass, fields
import numpy as np
import general_functions as gf
import pkg_db
import os
from PIL import Image
from version import version_str

"""
Images are a two-part system. The first file is the image header, containing all the important info. The second part
has the actual image data which uses the header data to transcribe that data to an actual image.
"""


@dataclass
class ImageHeader:
    FileSize: np.uint32 = np.uint32(0)  # 0
    Field4: np.uint32 = np.uint32(0)
    Field8: np.uint32 = np.uint32(0)
    FieldC: np.uint16 = np.uint16(0)
    Width: np.uint16 = np.uint16(0)  # E
    Height: np.uint16 = np.uint16(0)  # 10
    Field12: np.uint16 = np.uint16(0)
    Field14: np.uint16 = np.uint16(0)
    Identifier: np.uint16 = np.uint16(0)
    Field18: np.uint32 = np.uint32(0)
    Field1C: np.uint32 = np.uint32(0)
    Field20: np.uint32 = np.uint32(0)
    Field24: np.uint32 = np.uint32(0)


def get_header(file_hex):
    img_header = ImageHeader()
    for f in fields(img_header):
        if f.type == np.uint32:
            flipped = "".join(gf.get_flipped_hex(file_hex, 8))
            value = np.uint32(int(flipped, 16))
            setattr(img_header, f.name, value)
            file_hex = file_hex[8:]
        elif f.type == np.uint16:
            flipped = "".join(gf.get_flipped_hex(file_hex, 4))
            value = np.uint16(int(flipped, 16))
            setattr(img_header, f.name, value)
            file_hex = file_hex[4:]
    return img_header


def get_image_from_file(file_path):
    pkg_db.start_db_connection()
    file_name = file_path.split('/')[-1].split('.')[0]
    file_pkg = file_path.split('/')[-2]
    # To get the actual image data we need to pull this specific file's data from the database as it references its file
    # in its RefID.
    entries = pkg_db.get_entries_from_table(file_pkg, 'FileName, RefID, RefPKG, FileType')
    this_entry = [x for x in entries if x[0] == file_name][0]
    ref_file_name = f'{this_entry[2][2:]}-{gf.fill_hex_with_zeros(this_entry[1][2:], 8)}'
    if this_entry[-1] == 'Texture Header':
        header_hex = gf.get_hex_data(file_path)
        data_hex = gf.get_hex_data(f'{"/".join(file_path.split("/")[:-1])}/{ref_file_name}.bin')
    elif this_entry[-1] == 'Texture Data':
        header_hex = gf.get_hex_data(f'{"/".join(file_path.split("/")[:-1])}/{ref_file_name}.bin')
        data_hex = gf.get_hex_data(file_path)
    else:
        print("File given is not texture data or header.")
        return

    header = get_header(header_hex)
    dimensions = [header.Width, header.Height]
    img = Image.frombytes('RGBA', dimensions, bytes.fromhex(data_hex))
    img.show()


def get_images_from_pkg(pkg_path):
    pkg_db.start_db_connection()
    all_files = os.listdir(pkg_path)
    file_pkg = pkg_path.split('/')[-2]
    entries = pkg_db.get_entries_from_table(file_pkg, 'FileName, RefID, RefPKG, FileType')
    for file in all_files:
        file_name = file.split('.')[0]
        file_path = pkg_path + file
        # To get the actual image data we need to pull this specific file's data from the database as it references its
        #  file in its RefID.
        try:
            this_entry = [x for x in entries if x[0] == file_name][0]
        except IndexError:
            continue
        ref_file_name = f'{this_entry[2][2:]}-{gf.fill_hex_with_zeros(this_entry[1][2:], 8)}'
        if this_entry[-1] == 'Texture Header':
            header_hex = gf.get_hex_data(file_path)
            try:
                direc = [x for x in os.listdir(f'{version_str}/output_all/') if this_entry[2].lower()[2:] in x][0]
            except IndexError:
                continue
            data_hex = gf.get_hex_data(f'{version_str}/output_all/{direc}/{ref_file_name}.bin')
        else:
            # print("File given is not texture data or header.")
            continue

        try:
            os.mkdir(f'{version_str}/images_all/')
            os.mkdir(f'{version_str}/images_all/{file_pkg}/')
        except FileExistsError:
            try:
                os.mkdir(f'{version_str}/images_all/{file_pkg}/')
            except FileExistsError:
                pass
        header = get_header(header_hex)
        print(f'Getting image data for file {this_entry[0]}')
        dimensions = [int(header.Width), int(header.Height)]
        # print(dimensions)
        # print(f'{len(data_hex)}, need {int(dimensions[0]) * int(dimensions[1]) * 2 * 4}')  # 4 is RGBA
        if header.Identifier == 288:
            img = Image.frombytes('RGBA', dimensions, bytes.fromhex(data_hex))
        elif header.Identifier == 264:
            print(f'{len(data_hex)}, need {int(dimensions[0]) * int(dimensions[1]) * 2}')
            data_hex_split = [data_hex[i:i+2] for i in range(0, len(data_hex), 2)]
            for i in range(len(data_hex_split)):
                if data_hex_split[i] != "FF":
                    data_hex_split[i] = "00"
            data = ''.join(data_hex_split)
            img = Image.frombytes('L', dimensions, bytes.fromhex(data))
        elif header.Identifier == 260:  # moon/planet surfaces?  # eg 01a3-301
            print(f'Invalid identifier {header.Identifier}')
            continue # Don't know what to do to fix it
            print(f'{len(data_hex)}, need {int(dimensions[0]) * int(dimensions[1]) * 2 * 4}')  # 4 is RGBA

            img = Image.frombytes('RGBA', dimensions, bytes.fromhex(data_hex))
        else:
            print(f'Invalid identifier {header.Identifier}')
            continue
        img.save(f'{version_str}/images_all/{file_pkg}/{file_name}.png')


def get_images_in_pkgs():
    for pkg in os.listdir(f'{version_str}/output_all/'):
        if 'investment_globals' in pkg or 'ui' in pkg:
            get_images_from_pkg(f'{version_str}/output_all/{pkg}/')


def compare_images():
    import imagehash
    cutoff = 5
    old_version_str = '2_9_0_1'
    old_images_dir = f'{old_version_str}/images_all/'
    new_images_dir = f'{version_str}/images_all/'

    for folder in os.listdir(new_images_dir):
        for img in os.listdir(new_images_dir + folder):
            original = Image.open(new_images_dir + folder + '/' + img)
            hash0 = imagehash.average_hash(original)
            diff = Image.open(old_images_dir + folder + '/' + img)
            hash1 = imagehash.average_hash(diff)
            if hash0 - hash1 < cutoff:
                # print(f'{img} images are similar')
                pass
            else:
                print(f'{img} images are not similar')
        print(list(set(os.listdir(new_images_dir + folder)) - set(os.listdir(old_images_dir + folder))))

# get_image_from_file('2_9_0_1/output_all/ui_01a3/01A3-000009D6.bin')
# get_images_from_pkg(f'{version_str}/output_all/ui_01a3/')
# get_images_in_pkgs()
compare_images()

 # fix issues with some images needing try except