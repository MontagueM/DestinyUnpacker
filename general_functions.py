from dataclasses import fields
import numpy as np
from typing import List


def fill_hex_with_zeros(s, desired_length):
    """
    Takes a hex and fills it out with 0s at the beginning
    :param h: the hex string eg '1AC'
    :param desired_length: the length you want the end result to be eg 4
    :return: the filled out hex string of length desired_length eg '01AC'
    """
    return ("0"*desired_length + s)[-desired_length:]


def get_flipped_hex(h, length):
    """
    Flips the hex around so the data is read correctly eg 00 80 00 00 = 00 00 80 00. Takes every pair of bytes and
    flips them so AC 18 = 18 AC.
    :param h: the hex string to flip around
    :param length: how long this hex string is (len(h) doesn't work)
    :return: the flipped hex
    """
    if length % 2 != 0:
        print("Flipped hex length is not even.")
        return None
    return "".join(reversed([h[:length][i:i + 2] for i in range(0, length, 2)]))


def struct_as_hex(header):
    """
    Given a header struct it returns all the values but in hex
    :param header: header struct with all fields filled out
    :return: an array of all fields in hex
    """
    hex_fields = {}
    for field in fields(header):
        if field.type == np.uint32:
            hex_fields[field.name] = (fill_hex_with_zeros(hex(getattr(header, field.name))[2:].upper(), 8))
        elif field.type == np.uint16:
            hex_fields[field.name] = (fill_hex_with_zeros(hex(getattr(header, field.name))[2:].upper(), 4))
        elif field.type == np.uint8:
            hex_fields[field.name] = (fill_hex_with_zeros(hex(getattr(header, field.name))[2:].upper(), 2))
        elif field.type == List[np.uint8]:
            # print("Can't do array types yet")
            hex_fields[field.name] = ([])
    return hex_fields


def get_hex_data(direc):
    t = open(direc, 'rb')
    h = t.read().hex().upper()
    return h

