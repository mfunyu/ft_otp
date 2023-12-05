#!/usr/bin/python3
import argparse

def parse_args():
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-g", type=str)
	group.add_argument("-k", default="ft_otp.key", type=str)
	return parser.parse_args()

def main():
	args = parse_args()
	print(args)

main()
