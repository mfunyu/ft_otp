#!/usr/bin/python3
import argparse
import time
import hashlib
import base64
import qrcode
import hmac
import struct

time_step = 30
secret_key_file = "ft_otp.key"
issuer = "ft_otp"
email = "ft_otp@example.com"

def is_hex_string(s):
	try:
		# Attempt to convert the string to an integer with base 16 (hex)
		int(s, 16)
		return True
	except ValueError:
		return False

def id_valid_file(contents):
	if len(contents) < 64:
		print("./ft_otp: error: key must be at least 64 characters.")
		return False
	if not is_hex_string(contents):
		print("./ft_otp: error: key must be hexadecimal characters.")
		return False
	return True

def create_qrcode(secret_key):
	data = f'otpauth://totp/{issuer}:{email}?secret={secret_key}&issuer={issuer}'
	img = qrcode.make(data)
	img.save("ft_opt.png")
	print("QRcode can be found in ft_otp.png")

def generate_shared_secret_key(key_hex_file):
	try:
		with open(key_hex_file, 'r') as f:
			contents = f.read().strip()
			if not is_hex_string(contents):
				return
		hashed = hashlib.sha1(contents.encode())
		encoded = base64.b32encode(hashed.digest()).decode()
		with open(secret_key_file, "w") as f:
			f.write(encoded)
		print("Key was successfully saved in ft_otp.key")
		create_qrcode(encoded)

	except Exception as e:
		print(f"Error: {e}")

def debug_print(hmac_sha1, offset, chosen_bytes):
	hmac_sha1_hex = hmac_sha1.hexdigest()
	print("hmac_sha1:", hmac_sha1_hex)
	print("offset:", offset)
	print("chosen:", chosen_bytes.hex())
	for i in range(0, len(hmac_sha1_hex)//2):
		print(f"|{i: >2}", end="")
	print("|")
	i = 0
	while i in range(0, len(hmac_sha1_hex)):
		print(f"|{hmac_sha1_hex[i:i+2]}", end="")
		i = i + 2
	print("|")

def generate_otp(key_file):

	try:
		with open(key_file, 'r') as f:
			secret = f.read()
		secret_decoded = base64.b32decode(secret)

		timestamp = time.time()
		N = int(timestamp // time_step)
		time_key = N.to_bytes(8, "big")

		hmac_sha1 = hmac.new(secret_decoded, time_key, hashlib.sha1)
		hmac_sha1_bytes = hmac_sha1.digest()
		offset = hmac_sha1_bytes[-1] & 0xF
		chosen_bytes = hmac_sha1_bytes[offset:offset+4]

		#debug_print(hmac_sha1, offset, chosen_bytes)

		new_bin_value = ((chosen_bytes[0] & 0x7F) << 24)\
						+ ((chosen_bytes[1] & 0xFF) << 16)\
						+ ((chosen_bytes[2] & 0xFF) << 8)\
						+ ((chosen_bytes[3] & 0xFF))
		token = new_bin_value % 10**6
		token = f'{token:0>6}'
		print(f"Here is your OTP: [{token}]")

	except Exception as e:
		print(f"Error: {e}")

def parse_args():
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-g", type=str)
	group.add_argument("-k", type=str)
	return parser.parse_args()

def main():
	args = parse_args()
	if args.g:
		generate_shared_secret_key(args.g)
	elif args.k:
		generate_otp(args.k)

main()
