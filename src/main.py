import argparse
import errno
import ipaddress
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


DEFAULT_PORTS = [22, 80, 443, 8000]

MAX_SUBNET_HOSTS = 16

DEFAULT_WORKERS = 20

MAX_WORKERS = 100

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


def validate_target(value):
    if "/" not in value:
        return validate_ipv4(value)

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{value} is not a valid IPv4 network"
        )

    if network.version != 4:
        raise argparse.ArgumentTypeError(
            "Only IPv4 networks are currently supported"
        )

    hosts = list(network.hosts())

    if len(hosts) > MAX_SUBNET_HOSTS:
        raise argparse.ArgumentTypeError(
            f"Subnet contains {len(hosts)} usable hosts. "
            f"Current limit is {MAX_SUBNET_HOSTS} hosts"
        )

    return str(network)


def expand_targets(target):
    if "/" not in target:
        return [target]

    network = ipaddress.ip_network(target, strict=False)

    return [str(host) for host in network.hosts()]


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


def validate_workers(value):
    try:
        workers = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Worker count must be a number"
        )

    if workers < 1 or workers > MAX_WORKERS:
        raise argparse.ArgumentTypeError(
            f"Worker count must be between 1 and {MAX_WORKERS}"
        )

    return workers


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Discover open TCP ports on an authorised IPv4 host or subnet."
        )
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        type=validate_target,
        help="IPv4 address or CIDR network to scan",
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
        "-w",
        "--workers",
        type=validate_workers,
        default=DEFAULT_WORKERS,
        help=(
            f"Maximum concurrent workers "
            f"(default: {DEFAULT_WORKERS}, max: {MAX_WORKERS})"
        ),
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
        errno.EAGAIN,
        errno.EWOULDBLOCK,
    }:
        return "FILTERED/UNREACHABLE"

    return "ERROR"


def get_service_name(port):
    return SERVICE_NAMES.get(port, "unknown")


def build_result(port, state):
    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "service": get_service_name(port),
    }


def scan_ports(target, ports, workers=DEFAULT_WORKERS):
    results = []

    worker_count = min(workers, len(ports))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_port = {
            executor.submit(check_port, target, port): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]

            try:
                state = future.result()
            except Exception:
                state = "ERROR"

            results.append(
                build_result(port, state)
            )

    results.sort(key=lambda result: result["port"])

    return results


def scan_host(host, ports, workers):
    return {
        "host": host,
        "results": scan_ports(
            host,
            ports,
            workers,
        ),
    }


def scan_targets(targets, ports, workers=DEFAULT_WORKERS):
    host_results = []

    worker_count = min(workers, len(targets))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_host = {
            executor.submit(
                scan_host,
                host,
                ports,
                workers,
            ): host
            for host in targets
        }

        for future in as_completed(future_to_host):
            host = future_to_host[future]

            try:
                result = future.result()
            except Exception:
                result = {
                    "host": host,
                    "results": [],
                }

            host_results.append(result)

    host_results.sort(
        key=lambda item: ipaddress.ip_address(item["host"])
    )

    return host_results


def display_results(results):
    print(f"{'PORT':<10}{'STATE':<24}SERVICE")

    for result in results:
        port = result["port"]
        state = result["state"]
        service = result["service"]

        print(
            f"{str(port) + '/tcp':<10}"
            f"{state:<24}"
            f"{service}"
        )


def display_host_results(host_results):
    for host_result in host_results:
        print(f"\nHost: {host_result['host']}")

        display_results(
            host_result["results"]
        )


def write_json(target, results, output_path):
    data = {
        "target": target,
        "results": results,
    }

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=4,
        )


def write_multi_host_json(target, host_results, output_path):
    data = {
        "target": target,
        "hosts": host_results,
    }

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=4,
        )


def main():
    args = parse_arguments()

    target = args.target
    targets = expand_targets(target)
    workers = args.workers

    if args.ports:
        ports = args.ports
    elif args.port_range:
        ports = args.port_range
    else:
        ports = DEFAULT_PORTS

    if len(targets) == 1:
        print(
            f"Scanning {targets[0]} "
            f"with up to {workers} workers...\n"
        )

        results = scan_ports(
            targets[0],
            ports,
            workers,
        )

        display_results(results)

        if args.json_output:
            write_json(
                targets[0],
                results,
                args.json_output,
            )

            print(
                f"\nResults written to "
                f"{args.json_output}"
            )

        return

    print(
        f"Scanning {target} "
        f"({len(targets)} hosts) "
        f"with up to {workers} workers..."
    )

    host_results = scan_targets(
        targets,
        ports,
        workers,
    )

    display_host_results(host_results)

    if args.json_output:
        write_multi_host_json(
            target,
            host_results,
            args.json_output,
        )

        print(
            f"\nResults written to "
            f"{args.json_output}"
        )


if __name__ == "__main__":
    main()
