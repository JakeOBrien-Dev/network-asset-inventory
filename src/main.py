import socket
import sys

target = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)

result = sock.connect_ex((target, port))

if result == 0:
	print(f"{target}:{port} is OPEN")
else:
	print(f"{target}:{port} is CLOSED or UNREACHABLE")

sock.close()
