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
