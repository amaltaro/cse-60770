#!/usr/bin/env python3
### -*- coding: utf-8 -*-

import hashlib
import os
import string
import math
from itertools import chain, product


def brute_force(charset, min_length, max_length):
    """
    Generate a combination of passwords

    :param charset: string with all characters to be considered for the combination
    :param minlength: integer with minimum length of string
    :param maxlength: integer with maximum length of string
    :yield: string with a candidate password

    Adapted from: https://stackoverflow.com/questions/11747254/python-brute-force-algorithm
    """
    yield (''.join(candidate)
           for candidate in chain.from_iterable(product(charset, repeat=i)
                                                for i in range(min_length, max_length + 1)))


def get_pass_list():
    """
    Load all 3 text files and return a list of passwords hash
    """
    input_files = ["md5_30_passwords-pt1.txt",
                   "md5_30_passwords-pt2.txt",
                   "md5_30_passwords-pt3.txt"]

    passwd_list = []
    for f_name in input_files:
        with open(f_name) as fp:
            for line in fp:
                passwd_list.append(line.replace("\n", ""))
    print(f"Loaded a list of {len(passwd_list)} passwords.\n")
    #print(passwd_list)
    return passwd_list


### Execute the actual brute force logic
char_set = string.digits + string.ascii_letters + "&@#"

# Load password hashes from the 3 files
pass_list = get_pass_list()

found_passwds = []
for limit in range(3, 4):
    combs = math.pow(len(char_set), limit)
    print(f"Attempting full charset for size: {limit} with total combinations: {combs}")
    for gener_pass in brute_force(char_set, limit, limit):
        for passwd in gener_pass:
            passwd_hash = hashlib.md5(passwd.encode()).hexdigest()
            # Check if there is a match
            if passwd_hash in pass_list:
                print(f"{passwd}\t{passwd_hash}")
                found_passwds.append(passwd)

out_file = "cracked_passwords.txt"
print(f"Cracked a total of {len(found_passwds)} passwords.")
print(f"Writing them to {out_file} file")
with open(out_file, "w") as fp:
    for passwd in found_passwds:
        fp.write(passwd + "\n")
