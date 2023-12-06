#!/usr/bin/python3
import argparse
import time
import hashlib
import base64

time_step = 30
secret_key_file = "ft_otp.key"

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

def generate_shared_secret_key(key_hex_file):
	try:
		with open(key_hex_file, 'r') as f:
			contents = f.read()
			if not is_hex_string(contents):
				return
			print("Contents:", contents)
		hashed = hashlib.sha1(contents.encode())
		print("Hashed:", hashed.hexdigest())
		print("len:", len(hashed.hexdigest()))
		encoded = base64.b32encode(hashed.digest())
		print("Encoded:", encoded)
		with open(secret_key_file, "w") as f:
			f.write(encoded.decode())

		print("Key was successfully saved in ft_otp.key.")

	except Exception as e:
		print(f"Error: {e}")

def generate_otp(key_file):

	# time
	timestamp = time.time()

	N = int(timestamp // time_step)
	print(N)
	N_hex = hex(N)
	print(N_hex)

	# msg =
	# generate HMAC hash


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
