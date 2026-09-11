import argparse
import csv
import errno
import ipaddress
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
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
        network = ipaddress.ip_network(
            value,
            strict=False,
        )
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

    network = ipaddress.ip_network(
        target,
        strict=False,
    )

    return [
        str(host)
        for host in network.hosts()
    ]


def validate_ports(value):
    try:
        ports = [
            int(port)
            for port in value.split(",")
        ]
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
        start_text, end_text = value.split(
            "-",
            maxsplit=1,
        )

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

    return list(
        range(
            start,
            end + 1,
        )
    )


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
            "Discover TCP services and build an inventory "
            "of authorised IPv4 hosts."
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
        help="Write inventory report to a JSON file",
    )

    parser.add_argument(
        "--csv",
        dest="csv_output",
        help="Write inventory report to a CSV file",
    )

    return parser.parse_args()


def check_port(target, port):
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:

        sock.settimeout(1)

        try:
            result = sock.connect_ex(
                (target, port)
            )

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
    return SERVICE_NAMES.get(
        port,
        "unknown",
    )


def build_result(port, state):
    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "service": get_service_name(port),
    }


def scan_ports(
    target,
    ports,
    workers=DEFAULT_WORKERS,
):
    results = []

    worker_count = min(
        workers,
        len(ports),
    )

    with ThreadPoolExecutor(
        max_workers=worker_count
    ) as executor:

        future_to_port = {
            executor.submit(
                check_port,
                target,
                port,
            ): port
            for port in ports
        }

        for future in as_completed(
            future_to_port
        ):
            port = future_to_port[future]

            try:
                state = future.result()
            except Exception:
                state = "ERROR"

            results.append(
                build_result(
                    port,
                    state,
                )
            )

    results.sort(
        key=lambda result: result["port"]
    )

    return results


def build_host_inventory(host, results):
    open_services = []

    for result in results:
        if result["state"] == "OPEN":
            open_services.append(
                {
                    "port": result["port"],
                    "protocol": result["protocol"],
                    "service": result["service"],
                }
            )

    responsive = any(
        result["state"] in {
            "OPEN",
            "CLOSED",
        }
        for result in results
    )

    return {
        "host": host,
        "responsive": responsive,
        "open_service_count": len(
            open_services
        ),
        "open_services": open_services,
        "results": results,
    }


def scan_host(
    host,
    ports,
    workers,
):
    results = scan_ports(
        host,
        ports,
        workers,
    )

    return build_host_inventory(
        host,
        results,
    )


def scan_targets(
    targets,
    ports,
    workers=DEFAULT_WORKERS,
):
    host_results = []

    worker_count = min(
        workers,
        len(targets),
    )

    with ThreadPoolExecutor(
        max_workers=worker_count
    ) as executor:

        future_to_host = {
            executor.submit(
                scan_host,
                host,
                ports,
                workers,
            ): host
            for host in targets
        }

        for future in as_completed(
            future_to_host
        ):
            host = future_to_host[future]

            try:
                result = future.result()

            except Exception:
                result = {
                    "host": host,
                    "responsive": False,
                    "open_service_count": 0,
                    "open_services": [],
                    "results": [],
                }

            host_results.append(
                result
            )

    host_results.sort(
        key=lambda item: ipaddress.ip_address(
            item["host"]
        )
    )

    return host_results


def build_inventory_summary(host_results):
    hosts_scanned = len(
        host_results
    )

    responsive_hosts = sum(
        1
        for host in host_results
        if host["responsive"]
    )

    unresponsive_hosts = (
        hosts_scanned
        - responsive_hosts
    )

    hosts_with_open_services = sum(
        1
        for host in host_results
        if host["open_service_count"] > 0
    )

    open_tcp_services = sum(
        host["open_service_count"]
        for host in host_results
    )

    return {
        "hosts_scanned": hosts_scanned,
        "responsive_hosts": responsive_hosts,
        "unresponsive_hosts": unresponsive_hosts,
        "hosts_with_open_services": hosts_with_open_services,
        "open_tcp_services": open_tcp_services,
    }


def get_utc_timestamp():
    return datetime.now(
        timezone.utc
    ).isoformat(
        timespec="seconds"
    )


def build_inventory_report(
    target,
    host_results,
):
    return {
        "target": target,
        "scanned_at": get_utc_timestamp(),
        "summary": build_inventory_summary(
            host_results
        ),
        "hosts": host_results,
    }


def display_inventory(host_results):
    summary = build_inventory_summary(
        host_results
    )

    for host_result in host_results:
        host = host_result["host"]
        responsive = host_result["responsive"]
        services = host_result["open_services"]

        print(f"\nHost: {host}")

        if responsive:
            print("Status: responsive")
        else:
            print(
                "Status: no TCP response observed"
            )

        if services:
            print("Open services:")

            for service in services:
                print(
                    f"  "
                    f"{service['port']}/"
                    f"{service['protocol']}"
                    f"  "
                    f"{service['service']}"
                )
        else:
            print(
                "Open services: none detected"
            )

    print("\nSummary")

    print(
        f"Hosts scanned: "
        f"{summary['hosts_scanned']}"
    )

    print(
        f"Responsive hosts: "
        f"{summary['responsive_hosts']}"
    )

    print(
        f"No TCP response observed: "
        f"{summary['unresponsive_hosts']}"
    )

    print(
        f"Hosts with open services: "
        f"{summary['hosts_with_open_services']}"
    )

    print(
        f"Open TCP services: "
        f"{summary['open_tcp_services']}"
    )


def prepare_output_path(output_path):
    path = Path(
        output_path
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return path


def write_report_json(
    report,
    output_path,
):
    path = prepare_output_path(
        output_path
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
        )


def write_inventory_csv(
    report,
    output_path,
):
    path = prepare_output_path(
        output_path
    )

    fieldnames = [
        "scan_target",
        "scanned_at",
        "host",
        "responsive",
        "open_service_count",
        "port",
        "protocol",
        "service",
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for host_result in report["hosts"]:
            services = host_result[
                "open_services"
            ]

            if services:
                for service in services:
                    writer.writerow(
                        {
                            "scan_target": report[
                                "target"
                            ],
                            "scanned_at": report[
                                "scanned_at"
                            ],
                            "host": host_result[
                                "host"
                            ],
                            "responsive": str(
                                host_result[
                                    "responsive"
                                ]
                            ).lower(),
                            "open_service_count": (
                                host_result[
                                    "open_service_count"
                                ]
                            ),
                            "port": service[
                                "port"
                            ],
                            "protocol": service[
                                "protocol"
                            ],
                            "service": service[
                                "service"
                            ],
                        }
                    )

            else:
                writer.writerow(
                    {
                        "scan_target": report[
                            "target"
                        ],
                        "scanned_at": report[
                            "scanned_at"
                        ],
                        "host": host_result[
                            "host"
                        ],
                        "responsive": str(
                            host_result[
                                "responsive"
                            ]
                        ).lower(),
                        "open_service_count": 0,
                        "port": "",
                        "protocol": "",
                        "service": "",
                    }
                )


def write_json(
    target,
    results,
    output_path,
):
    data = {
        "target": target,
        "results": results,
    }

    path = prepare_output_path(
        output_path
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


def write_inventory_json(
    target,
    host_results,
    output_path,
):
    report = build_inventory_report(
        target,
        host_results,
    )

    write_report_json(
        report,
        output_path,
    )


def main():
    args = parse_arguments()

    target = args.target
    targets = expand_targets(
        target
    )

    workers = args.workers

    if args.ports:
        ports = args.ports

    elif args.port_range:
        ports = args.port_range

    else:
        ports = DEFAULT_PORTS

    if len(targets) == 1:
        host_results = [
            scan_host(
                targets[0],
                ports,
                workers,
            )
        ]

    else:
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

    display_inventory(
        host_results
    )

    report = build_inventory_report(
        target,
        host_results,
    )

    if args.json_output:
        write_report_json(
            report,
            args.json_output,
        )

        print(
            f"\nJSON report written to "
            f"{args.json_output}"
        )

    if args.csv_output:
        write_inventory_csv(
            report,
            args.csv_output,
        )

        print(
            f"CSV report written to "
            f"{args.csv_output}"
        )


if __name__ == "__main__":
    main()
