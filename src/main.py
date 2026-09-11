import argparse
import errno
import ipaddress
import json
import socket
from pathlib import Path


DEFAULT_PORTS = [22, 80, 443, 8000]

SERVICE_NAMES = {
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3389: "rdp",
    8000: "http-alt",
}


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


def validate_port_range(value):
    try:
        start_text, end_text = value.split("-", maxsplit=1)
        start = int(start_text)
        end = int(end_text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Port range must use the format START-END"
        )

    if start < 1 or start > 65535:
        raise argparse.ArgumentTypeError(
            f"Start port {start} is outside the valid range 1-65535"
        )

    if end < 1 or end > 65535:
        raise argparse.ArgumentTypeError(
            f"End port {end} is outside the valid range 1-65535"
        )

    if start > end:
        raise argparse.ArgumentTypeError(
            "Start port must not be greater than end port"
        )

    return list(range(start, end + 1))


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

    port_group = parser.add_mutually_exclusive_group()

    port_group.add_argument(
        "-p",
        "--ports",
        type=validate_ports,
        help="Comma-separated TCP ports to scan",
    )

    port_group.add_argument(
        "-r",
        "--range",
        dest="port_range",
        type=validate_port_range,
        help="TCP port range to scan, for example 20-100",
    )

    parser.add_argument(
        "--json",
        dest="json_output",
        help="Write scan results to a JSON file",
    )

    return parser.parse_args()


def check_port(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)

        try:
            result = sock.connect_ex((target, port))
        except socket.timeout:
            return "FILTERED/UNREACHABLE"
        except OSError:
            return "ERROR"

    if result == 0:
        return "OPEN"

    if result == errno.ECONNREFUSED:
        return "CLOSED"

    if result in {
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
    }:
        return "FILTERED/UNREACHABLE"

    return "ERROR"


def get_service_name(port):
    return SERVICE_NAMES.get(port, "unknown")


def scan_ports(target, ports):
    results = []

    for port in ports:
        state = check_port(target, port)
        service = get_service_name(port)

        result = {
            "port": port,
            "protocol": "tcp",
            "state": state,
            "service": service,
        }

        results.append(result)

    return results


def display_results(results):
    print(f"{'PORT':<10}{'STATE':<24}SERVICE")

    for result in results:
        port = result["port"]
        state = result["state"]
        service = result["service"]

        print(f"{str(port) + '/tcp':<10}{state:<24}{service}")


def write_json(target, results, output_path):
    data = {
        "target": target,
        "results": results,
    }

    path = Path(output_path)

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def main():
    args = parse_arguments()

    target = args.target

    if args.ports:
        ports = args.ports
    elif args.port_range:
        ports = args.port_range
    else:
        ports = DEFAULT_PORTS

    print(f"Scanning {target}...\n")

    results = scan_ports(target, ports)

    display_results(results)

    if args.json_output:
        write_json(target, results, args.json_output)
        print(f"\nResults written to {args.json_output}")


if __name__ == "__main__":
    main()
