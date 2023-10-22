# Binary decoding based on code by David Schuetz as dschuetz
# in https://github.com/dschuetz/1password
# With CC-BY-SA license https://github.com/dschuetz/1password/blob/master/LICENSE.md

# SQLite processing and opdata1 unpacking borrowed from John the Ripper's 1password2john.py extraction
# script on https://github.com/openwall/john/blob/bleeding-jumbo/run/1password2john.py

# Written by Dhiru Kholia <dhiru at openwall.com> in July 2012 for JtR project.
# Copyright (c) 2012-2013, Dhiru Kholia.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# Code borrowed from https://github.com/Roguelazer/onepasswordpy
#
# Copyright (c) 2013, James Brown
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# Code borrowed from https://bitbucket.org/gwik/agilekeychain
#
# Copyright (c) 2009 Antonin Amand <antonin.amand@gmail.com>
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appear in all copies and that
# both that copyright notice and this permission notice appear in
# supporting documentation.
#
# THE AUTHOR PROVIDES THIS SOFTWARE 'AS IS' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
# EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys
import struct
import base64
import sqlite3
import binascii
import json
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
import re

# David Schuetz's comments:
# "
# The strings stored by 1Password don't always have padding characters at the
#   end. So we try multiple times until we get a good result.
#
# Also, 1Password uses url-safe encoding with - and _ replacing + and /.
# "
def opb64d(b64dat):
    try:
        out = base64.b64decode(b64dat, altchars='-_')

    except:
        try:
            out = base64.b64decode(b64dat + '=', altchars='-_')

        except:
            try:
                out = base64.b64decode(b64dat + '==', altchars='-_')
            except:
                print ("Problem b64 decoding string: %s" % (b64dat))
                sys.exit(1)

    return out

# David Schuetz's comments:
# "
# Simple - encode something in base64 but use URL-safe
#   alt chars - and _ instead of + and /
# "
def opb64e(dat):
    return base64.b64encode(dat, altchars=b'-_')

# David Schuetz's comments:
# "
# Collects binary data. Then, try to decode it. First 
#   assume it's hex, then try base64, both using
#   1Password tricks, then just plain vanilla base64.
#
# Not exactly bulletproof. (like, abcd1234 is both a hex
#   string and a perfectly acceptable Base-64 encoding.)
#   But for what we're doing (binary encodings of random
#   keys, IVs, and ciphertexts), it's incredibly unlikely
#   that any base-64 string would present as valid hex, 
#   etc.
#
# See also all my previous warnings about using any of 
#   tnis code for something that actually matters. 
# "
def get_binary(prompt):
    raw_dat = prompt
    try:
        bin = binascii.a2b_hex(raw_dat)

    except:
        try:
            bin = opb64d(raw_dat)
 
        except:
            try:
                bin = base64.b64decode(raw_dat)

            except:
                print ("Unable to decode the input. Enter in hex or base64.")
                sys.exit(1)

    return bin

PY3 = sys.version_info[0] == 3
PMV = sys.version_info[1] >= 6

def opdata1_unpack(data):
    HEADER_LENGTH = 8
    TOTAL_HEADER_LENGTH = 32
    HMAC_LENGTH = 32
    if data[:HEADER_LENGTH] != b"opdata01":
        data = base64.b64decode(data)
    if PY3 or PMV:
        MAGIC = b"opdata01"
    else:
        MAGIC = "opdata01"

    if data[:HEADER_LENGTH] != MAGIC:
        raise TypeError("expected opdata1 format message")
    plaintext_length, iv = struct.unpack("<Q16s",
                data[HEADER_LENGTH:TOTAL_HEADER_LENGTH])
    cryptext = data[TOTAL_HEADER_LENGTH:-HMAC_LENGTH]
    expected_hmac = data[-HMAC_LENGTH:]
    hmac_d_data = data[:-HMAC_LENGTH]
    return plaintext_length, iv, cryptext, expected_hmac, hmac_d_data

def process_sqlite_json(filename):
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    account_row = cursor.execute('SELECT data FROM accounts')
    cursor = db.cursor()
    keyset1_rows = cursor.execute('SELECT data FROM account_objects')

    account_json, = account_row.fetchone()
    keyset_json, = keyset1_rows.fetchone()

    account = json.loads(account_json)
    keyset = json.loads(keyset_json)
    enc_sym_key = json.loads(keyset['enc_sym_key'])

    email = str(account['user_email'])
    secret_key = account['sign_in_provider']['secret_key']
    secret_key_version = str.encode(secret_key[0:2])
    secret_key_account_id = str.encode(secret_key[3:9])
    secret_key_secret = str.encode(re.sub('-', '', secret_key[10:]))
    salt = get_binary(enc_sym_key['p2s'])
    algorithm = str.encode(str(enc_sym_key['alg']))
    iterations = enc_sym_key['p2c']
    header = b"opdata01"
    iv = get_binary(enc_sym_key['iv'])
    data = get_binary(enc_sym_key['data'])
    ct = data[:-16]
    tag = data[-16:]
    
    hkdf_salt = HKDF(salt, 32, str.encode(email), SHA256, 1, algorithm)
    hkdf_key = HKDF(secret_key_secret, 32, secret_key_account_id, SHA256, 1, secret_key_version)

    sys.stdout.write("$mobilekeychain$%s$%s$%s$%s$%s$%s$%s" % (
        email,
        binascii.hexlify(hkdf_salt).decode("ascii"),
        binascii.hexlify(hkdf_key).decode("ascii"),
        iterations,
        binascii.hexlify(iv).decode("ascii"),
        binascii.hexlify(ct).decode("ascii"),
        binascii.hexlify(tag).decode("ascii")))
          
sqlite_path = "1password.sqlite"
process_sqlite_json(sqlite_path)
