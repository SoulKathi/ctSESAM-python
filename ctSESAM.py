#!/usr/bin/python3
# -*- coding: utf-8 -*-

import getpass
from hashlib import pbkdf2_hmac
import json
import sys

with open("config.json") as conf:
    config = json.load(conf)

small_letters = list(config['small_letters'])
big_letters = list(config['big_letters'])
numbers = list(config['numbers'])
special_characters = list('special_characters')
salt = config['salt']
passwd_length = config['passwd_length']


def convert_bytes_to_password(hashed_bytes, length):
    number = int.from_bytes(hashed_bytes, byteorder='big')
    password = ''
    while number > 0 and len(password) < length:
        password = password + password_characters[number % len(password_characters)]
        number = number // len(password_characters)
    return password

master_password = getpass.getpass(prompt='Masterpasswort: ')
domain = input('Domain: ')

# domain specific configuration
if domain == 'www.twitter.com':
    special_characters = list('!$%/()+-_')
if domain == 'www.facebook.com':
    special_characters = list('!"§$%&/()=?{[]}\+*~#,;.:-_<>|@€ ')
    salt = 'apple'
if domain == 'www.instagram.com':
    passwd_length = 8
    salt = 'Nina'

password_characters = small_letters + big_letters + numbers + special_characters
while len(domain) < 1:
    print('Bitte gib die Domain an, für die das Passwort generiert werden soll.')
    domain = input('Domain: ')
hash_string = domain + master_password
hashed_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'), salt.encode('utf-8'), 4096)
print('Passwort: ' + convert_bytes_to_password(hashed_bytes, passwd_length))
