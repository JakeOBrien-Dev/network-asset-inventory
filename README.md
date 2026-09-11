# Network Asset Inventory

## Overview

This is a Python based cyber security project that is designed to diver devices and identify any exposed network serivces on authorised networks

The goal of this project is to improve my understanding of networking, TCP connections, python socket programming, network reconnaissance, asset discorvery and secure software development.

rather than relying entirely on existing tools like Nmap, this project will build core scanning functionality from the ground up so that i can understand how network discovery works at a lower level.

## Goals

The main goals of this project is to:

- Learn how TCP connections work.
- Understand how ports and networking services are exposed.
- Practise Python networking and socket programming.
- Discover hosts and services on authorised networks.
- Produce structured network asset invetories.
- Develop a secure and maintainable command-line tool.
- Practice Git, GitHub, documentation and software testing.

## Usage

#### Activate the virtual environment:

source .venv/bin/activate

#### Scan the default TCP ports:

python3 src/main.py --target 127.0.0.1

#### Scan specific TCP ports:

python3 src/main.py --target 127.0.0.1

#### Short argument forms are also supported:

python3 src/main.py -t 127.0.0.1 -p 22,80,443

#### Display command-line help:

python3 src/main.py --help

#### Export scan results to JSON:

python3 src/main.py --target 127.0.0.1 --ports 22,80,443 --json output/scan.json

(Real scan output stored under output/ is excluded from Git to avoid accidentally publishing potentially sensitive infrastructure information.) 

#### Scan a TCP port range:

python3 src/main.py --target 127.0.0.1 --range 20-100

or

python3 src/main.py -t 127.0.0.1 -r 20-100

### Concurrent scanning

The scanner uses a bounded thread pool to perform multiple TCP connection attempts concurrently.

The default worker count is 20:

python3 src/main.py --target 127.0.0.1 --range 1-100

#### A custom worker count can be selected with -w or --workers:

python3 src/main.py --target 127.0.0.1 --range 1-100 --workers 10


#### Scan a small IPv4 subnet using CIDR notation:

python3 src/main.py --target 127.0.0.0/30 --ports 8000,8001

(The scanner expands supported IPv4 CIDR networks into individual usable host addresses and scans each host separately.)
(Subnet scanning is currently limited to 16 usable hosts while scanning stays sequential.)

## Asset Inventory

The scanner converts raw TCP scan results into a higher-level asset inventory.

Each host record includes:

- Whether the host produced a TCP response
- Number of detected open TCP services
- Open service details
- Full underlying scan results

A host is considered responsive when at least one scanned TCP port returns either `OPEN` or `CLOSED`, because both states indicate that the target responded.

Example output:

Host: 127.0.0.1
Status: responsive
Open services:
  8000/tcp  http-alt

Host: 127.0.0.2
Status: no TCP response observed
Open services: none detected

Summary
Responsive hosts: 1/2
Open TCP services: 1

## Testing

This project uses Python's built in 'unittest' framework.

Run the full test suite from the project root:

python3 -m unittest discover -s tests -v

#### Current tests cover:

- Valid IPv4 addresses
- Invalid IPv4 adresses
- IPv6 rejection
- Valid port lists
- Non-numeric ports
- Out-of-range ports
- Known service mappings
- Unknown service handling
- Structured scan-result generation
- JSON report creation
- IPv4 subnet validation
- CIDR network normalisation
- Host expansion from IPv4 subnets
- Subnet size limits
- Multi-host JSON reports
- Socket error regression handling
- Worker-count validation
- Concurrent port scan result handling
- Deterministic host ordering after concurrent scans
- Responsive and unresponsive host classification
- Open-service extraction
- Host inventory construction
- Inventory JSON summary generation

## Planned Features

Planned functions for this tool will include:

- Scan individual IP addresses and TCP ports.
- Scan multiple commmon TCP ports.
- Accept IP addresses and subnets as command line input.
- Identify reachable hosts.
- Record discovered open ports.
- Attempt basic service identification.
- Support configuarable connection timeouts.
- Export scan results to JSON and CSV.
- Add timestamps to scan results.
- Provide clear command-line output.
- Handle invalid input and network errors safely.
- Add automated tests.
- Produce sanitised sample output for documentation.

## Security

Real scan results may contain sesitive data such as private IP addresses, hostnames and exposed services so I will not be commiting real world scan results into this repo I will use sanitised or sythentic examples instead.


## Project Status

The tool currently supports:

- IPv4 target validation
- TCP connection scanning
- Default port scanning
- User-selectable TCP ports
- Port range validation
- Command-line help and error handling
- Differenciated TCP connection states
- Conventional service-name mapping
- Improved tabular scan output
- TCP port-range scanning
- Validation of malformed, backwards, and out-of-range port ranges
- Mutually exclusive custom port-list and port-range options
- 15 automated unit tests
- Individual IPv4 host scanning
- Small IPv4 subnet scanning using CIDR notation
- Multi-host scan results
- Multi-host JSON export
- Cross-platform socket error handling
- 23 automated unit tests
- GitHub Actions continuous integration
- Concurrent TCP scanning using bounded thread pools
- Configurable worker count
- Concurrent multi-host scanning
- Deterministic result ordering
- Worker-count validation
- 28 automated unit tests
- GitHub Actions continuous integration
- Host-level asset inventory records
- Responsive-host identification
- Open-service summaries
- Inventory-level JSON reporting
- Detailed raw scan results retained alongside asset summaries
- 30 automated unit tests
