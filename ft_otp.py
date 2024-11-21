#!/bin/env python3

# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    ft_otp.py                                          :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: frcharbo <frcharbo@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/11/20 23:20:36 by frcharbo          #+#    #+#              #
#    Updated: 2024/11/21 02:27:33 by frcharbo         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

import argparse
import time
import struct
import hmac
import hashlib
import base64
import string
import sys
import qrcode

def read_key_from_file(filename):
    try:
        with open(filename, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        print(f"ERROR: The file '{filename}' was not found.")
        sys.exit(1)  # Exit the program with an error status
    except PermissionError:
        print(f"ERROR: Permission denied to read the file '{filename}'.")
        sys.exit(1)  # Exit the program with an error status
    except Exception as e:
        print(f"ERROR: An unexpected error occurred while reading the file: {e}")
        sys.exit(1)  # Exit the program with an error status

def pad_to_64(short_byte_key):
    k0 = short_byte_key + b'\x00' * (64 - len(short_byte_key))
    return k0

def get_counter():
    current_time_step = int(time.time() // 30)
    # print(current_time_step)
    counter_bytes = struct.pack(">Q", current_time_step) #calculate the 8-byte big endian (> means big endian and Q means ULLI i.e. 64 bits or 8 bytes)
    # print(counter_bytes)
    return counter_bytes

def caesar_cipher(key, shift=1):
    shifted_key = []
    for char in key:
        # Apply Caesar cipher to each character because fuck the subject
        if '0' <= char <= '9':
            shifted_key.append(chr(((ord(char) - ord('0') + shift) % 10) + ord('0')))
        elif 'a' <= char <= 'f':
            shifted_key.append(chr(((ord(char) - ord('a') + shift) % 6) + ord('a')))
        elif 'A' <= char <= 'F':
            shifted_key.append(chr(((ord(char) - ord('A') + shift) % 6) + ord('A')))
        else:
            shifted_key.append(char)
    return ''.join(shifted_key)

def calculate_k0(secret_byte_key):
    if len(secret_byte_key) < 64:
        k0 = pad_to_64(secret_byte_key)
    elif len(secret_byte_key) == 64:
        k0 = secret_byte_key
    else:
        k0_20byte = hashlib.sha1(secret_byte_key).digest()
        k0 = pad_to_64(k0_20byte)
    return k0

def hmac_at_home(secret_key, counter):

    k0 = calculate_k0(secret_key)
    
    ipad = bytes(a ^ b for a, b in zip(k0, bytes([0x36] * 64)))
    opad = bytes(a ^ b for a, b in zip(k0, bytes([0x5C] * 64)))
    #k0 XOR ipad
    inner = hashlib.sha1(ipad + counter).digest()
    #apply XOR opad
    hmac_result = hashlib.sha1(opad + inner).digest()
    return hmac_result

def hmac_to_otp(hmac_result):
    #extract 4 byes to get our 6 digit OTP
    offset = hmac_result[-1] & 0x0F
    # print(f"Offset: {offset}")
    truncated_hash = hmac_result[offset:offset + 4]
    # print(f"Truncated hash: {truncated_hash}")
    code = int.from_bytes(truncated_hash, byteorder='big') & 0x7FFFFFFF #mask to ensure its +ve
    # print(f"Truncated integer: {code}")
    otp = code % 10**6
    # print(f"Generated OTP: {otp:06d}")
    otp_str = str(otp).zfill(6)
    return(otp_str)
    
def create_qr_code(seed):
    
    byte_key = bytes.fromhex(seed)
    seed = base64.b32encode(byte_key).decode()

    account_name = "user@example.com"
    otpauth_url = f'otpauth://totp/MyService:{account_name}?secret={seed}&issuer=MyService'
    qr = qrcode.make(otpauth_url)
    qr.save("totp_qr_code.png")
    print("QR code saved as 'totp_qr_code.png'")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="FT One-time-passcode")
    parser.add_argument("key_file", help="File that contains 64 character hexadecimal key")
    parser.add_argument("-g",  action="store_true", help="Safe Key in ft_opt.key")
    parser.add_argument("-k",  action="store_true", help="Generate one-time-passcode based on the provided key")
    parser.add_argument("-q",  action="store_true", help="Generate QR code with seed generation")
    args = parser.parse_args()

    if not (args.g or args.k):
        parser.print_help()
        sys.exit()
    
    input_key = read_key_from_file(args.key_file).strip()
    secret_key = input_key
    print(secret_key)
    if len(secret_key) < 64:
        print("ERROR_KEY - Please provide a key longer than 64 characters.")
        sys.exit()
    
    if len(secret_key) % 2 != 0:
        secret_key = "0" + secret_key

    if all(c in string.hexdigits for c in secret_key):
        byte_key = bytes.fromhex(secret_key)
    else:
        print("ERROR_KEY - Please ensure that your key only contains hexadecimal characters (0-9 or A - F)")
        sys.exit()
    
    if args.q and len(secret_key) != 64:
        print("ERROR_QR - QR code only compatible with key of length 64")
    elif args.q:
        create_qr_code(input_key)

    
    if args.g:
        shifted_key = caesar_cipher(input_key, shift=1) #LOL
        with open("ft_otp.key", "w") as key_file:
            key_file.write(shifted_key)
            print("  .・。.・✭゜・.・✫・゜・。. .・。.・゜✭・.・✫・゜・。. .・。.・゜✭・.・✫・゜・。. .・。.・゜✭・.・")
            print("･ﾟ✧   Your key was successfully and gracefully encrypted in your beloved ft_otp.key file      ﾟ･✧")
            print("  ゜・゜✭・.・✫・゜・。. .・。.・゜✭・.・✫・゜・。. .・。.・゜✭・.・✫・゜・。. .・。.・゜✭・.・✫・゜")

    if args.k:
        counter_bytes = get_counter()
        hmac_result = hmac_at_home(byte_key, counter_bytes)
        # print(f"HMAC-SHA-1 result: {hmac_result}")
        one_time_passcode = hmac_to_otp(hmac_result)
        print(one_time_passcode)
