import argparse
import ipaddress
import socket


DEFAULT_PORTS = [22, 80, 443, 8000]


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


def validate_ports(value):
    try:
        ports = [int(port) for port in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Ports must be comma-separated numbers"
        )

    for port in ports:
        if port < 1 or port > 65535:
            raise argparse.ArgumentTypeError(
                f"Port {port} is outside the valid range 1-65535"
            )

    return ports


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

    parser.add_argument(
        "-p",
        "--ports",
        type=validate_ports,
        default=DEFAULT_PORTS,
        help="Comma-separated TCP ports to scan",
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
    ports = args.ports

    print(f"Scanning {target}...\n")

    for port in ports:
        if check_port(target, port):
            print(f"{port}/tcp\tOPEN")
        else:
            print(f"{port}/tcp\tCLOSED/UNREACHABLE")


if __name__ == "__main__":
    main()
