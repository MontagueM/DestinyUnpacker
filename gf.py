import os


def fill_hex_with_zeros(s, desired_length):
    return ("0"*desired_length + s)[-desired_length:]


def get_flipped_bin(h, length):
    if length % 2 != 0:
        print("Flipped bin length is not even.")
        return None
    return h[:length][::-1]


def mkdir(path):
    try:
        os.mkdir(path)
    except FileExistsError:
        pass


def get_int32(hx, offset):
    return int.from_bytes(hx[offset:offset+4], byteorder='little')


def get_int16(hx, offset):
    return int.from_bytes(hx[offset:offset+2], byteorder='little')
