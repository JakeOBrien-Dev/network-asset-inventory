import argparse
import ipaddress
import socket

PORTS = [22, 80, 443, 8000]


def validate_ipv4(value):
	try:
		address = ipaddress.ip_address(value)
	except ValueError:
		raise argparse.ArgumentTypeError(
			f"{value} is not a valid IP address"
		)

	if address.version != 4:
		raise argparse.ArgumentTypeError(
			"Only IPv4 addresses are currently supported"
		)
	
	return str(address)

def parse_arguments():
	parser = argparse.ArgumentParser(
		description="Discover open TCP ports on an authorised target."
	)

	parser.add_argument(
		"-t",
		"--target",
		required=True,
		type=validate_ipv4,
		help="IPv4 address to scan",
	)

	return parser.parse_args()

def check_port(target, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(1)

	result = sock.connect_ex((target, port))

	sock.close()

	return result == 0

def main():
	args = parse_arguments()
	target = args.target

	print(f"Scanning {target}...\n")

	for port in PORTS:
		if check_port(target, port):
			print(f"{port}/tcp\tOPEN")
		else:
			print(f"{port}/tcp\tCLOSED/UNREACHABLE")


if __name__ == "__main__":
	main()
