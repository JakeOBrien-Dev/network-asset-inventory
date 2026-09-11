import socket
import sys

def check_port(target, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(1)

	result = sock.connect_ex((target, port))
	
	sock.close()

	return result == 0

target = sys.argv[1]

ports = [22, 80, 443, 8000]

print(f"Scanning {target}...\n")

for port in ports:
	if check_port(target, port):
		print(f"{port}/tcp\tOPEN")
	else:
		print(f"{port}/tcp\tCLOSED/UNREACHABLE")
