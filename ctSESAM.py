#!/usr/bin/python3
# -*- coding: utf-8 -*-

import getpass
from hashlib import pbkdf2_hmac
import json
import sys

with open("config.json") as conf:
    config = json.load(conf)

def convert_bytes_to_password(hashed_bytes, length):
    number = int.from_bytes(hashed_bytes, byteorder='big')
    password = ''
    while number > 0 and len(password) < length:
        password = password + password_characters[number % len(password_characters)]
        number = number // len(password_characters)
    return password

master_password = getpass.getpass(prompt='Masterpasswort: ')
domain = input('Domain: ')
while len(domain) < 1:
    print('Bitte gib die Domain an, für die das Passwort generiert werden soll.')
    domain = input('Domain: ')

try:
    small_letters = list(config[domain]['small_letters'])
    pass
except KeyError as identifier:
    small_letters = list(config['small_letters'])
    pass

try:
    big_letters = list(config[domain]['big_letters'])
    pass
except KeyError as identifier:
    big_letters = list(config['big_letters'])
    pass

try:
    numbers = list(config[domain]['numbers'])
    pass
except KeyError as identifier:
    numbers = list(config['numbers'])
    pass

try:
    special_characters = list(config[domain]['special_characters'])
    pass
except KeyError as identifier:
    special_characters = list(config['special_characters'])
    pass

try:
    salt = config[domain]['salt']
    pass
except KeyError as identifier:
    salt = config['salt']
    pass

try:
    passwd_length = config[domain]['passwd_length']
    pass
except KeyError as identifier:
    passwd_length = config['passwd_length']
    pass

password_characters = small_letters + big_letters + numbers + special_characters
hash_string = domain + master_password
hashed_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'), salt.encode('utf-8'), 4096)
print('Passwort: ' + convert_bytes_to_password(hashed_bytes, passwd_length))