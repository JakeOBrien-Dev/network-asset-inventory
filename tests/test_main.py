import argparse
import errno
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.main import (
    build_host_inventory,
    check_port,
    expand_targets,
    get_service_name,
    scan_ports,
    scan_targets,
    validate_ipv4,
    validate_port_range,
    validate_ports,
    validate_target,
    validate_workers,
    write_inventory_json,
    write_json,
)


class TestIPv4Validation(unittest.TestCase):
    def test_valid_ipv4(self):
        result = validate_ipv4("127.0.0.1")
        self.assertEqual(result, "127.0.0.1")

    def test_invalid_ipv4(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ipv4("banana")

    def test_ipv6_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ipv4("::1")


class TestTargetValidation(unittest.TestCase):
    def test_valid_single_target(self):
        result = validate_target("127.0.0.1")
        self.assertEqual(result, "127.0.0.1")

    def test_valid_subnet(self):
        result = validate_target("127.0.0.1/30")
        self.assertEqual(result, "127.0.0.0/30")

    def test_invalid_subnet(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_target("192.168.1.0/banana")

    def test_subnet_too_large(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_target("192.0.2.0/24")


class TestTargetExpansion(unittest.TestCase):
    def test_single_target_expansion(self):
        result = expand_targets("127.0.0.1")
        self.assertEqual(result, ["127.0.0.1"])

    def test_subnet_target_expansion(self):
        result = expand_targets("127.0.0.0/30")

        self.assertEqual(
            result,
            [
                "127.0.0.1",
                "127.0.0.2",
            ],
        )


class TestPortValidation(unittest.TestCase):
    def test_valid_ports(self):
        result = validate_ports("22,80,443")
        self.assertEqual(result, [22, 80, 443])

    def test_non_numeric_port(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ports("22,banana,443")

    def test_port_too_high(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ports("70000")

    def test_port_zero(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ports("0")


class TestPortRangeValidation(unittest.TestCase):
    def test_valid_port_range(self):
        result = validate_port_range("20-25")
        self.assertEqual(
            result,
            [20, 21, 22, 23, 24, 25],
        )

    def test_malformed_port_range(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_port_range("20")

    def test_backwards_port_range(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_port_range("100-20")

    def test_port_range_too_high(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_port_range("65000-70000")


class TestWorkerValidation(unittest.TestCase):
    def test_valid_worker_count(self):
        result = validate_workers("20")
        self.assertEqual(result, 20)

    def test_zero_workers_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_workers("0")

    def test_too_many_workers_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_workers("101")

    def test_non_numeric_workers_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_workers("banana")


class TestSocketStates(unittest.TestCase):
    @patch("src.main.socket.socket")
    def test_eagain_is_filtered_or_unreachable(self, mock_socket):
        mock_sock = MagicMock()

        mock_socket.return_value.__enter__.return_value = mock_sock
        mock_sock.connect_ex.return_value = errno.EAGAIN

        result = check_port(
            "127.0.0.2",
            8000,
        )

        self.assertEqual(
            result,
            "FILTERED/UNREACHABLE",
        )


class TestServiceNames(unittest.TestCase):
    def test_known_service(self):
        self.assertEqual(
            get_service_name(443),
            "https",
        )

    def test_unknown_service(self):
        self.assertEqual(
            get_service_name(54321),
            "unknown",
        )


class TestInventoryModel(unittest.TestCase):
    def test_responsive_host_inventory(self):
        results = [
            {
                "port": 8000,
                "protocol": "tcp",
                "state": "OPEN",
                "service": "http-alt",
            },
            {
                "port": 8001,
                "protocol": "tcp",
                "state": "CLOSED",
                "service": "unknown",
            },
        ]

        inventory = build_host_inventory(
            "127.0.0.1",
            results,
        )

        self.assertTrue(
            inventory["responsive"]
        )

        self.assertEqual(
            inventory["open_service_count"],
            1,
        )

        self.assertEqual(
            inventory["open_services"],
            [
                {
                    "port": 8000,
                    "protocol": "tcp",
                    "service": "http-alt",
                }
            ],
        )

        self.assertEqual(
            inventory["results"],
            results,
        )

    def test_unresponsive_host_inventory(self):
        results = [
            {
                "port": 8000,
                "protocol": "tcp",
                "state": "FILTERED/UNREACHABLE",
                "service": "http-alt",
            },
            {
                "port": 8001,
                "protocol": "tcp",
                "state": "FILTERED/UNREACHABLE",
                "service": "unknown",
            },
        ]

        inventory = build_host_inventory(
            "127.0.0.2",
            results,
        )

        self.assertFalse(
            inventory["responsive"]
        )

        self.assertEqual(
            inventory["open_service_count"],
            0,
        )

        self.assertEqual(
            inventory["open_services"],
            [],
        )


class TestScanResults(unittest.TestCase):
    @patch("src.main.check_port")
    def test_scan_ports_returns_structured_results(
        self,
        mock_check_port,
    ):
        mock_check_port.side_effect = [
            "OPEN",
            "CLOSED",
        ]

        results = scan_ports(
            "127.0.0.1",
            [8000, 8001],
            workers=2,
        )

        expected = [
            {
                "port": 8000,
                "protocol": "tcp",
                "state": "OPEN",
                "service": "http-alt",
            },
            {
                "port": 8001,
                "protocol": "tcp",
                "state": "CLOSED",
                "service": "unknown",
            },
        ]

        self.assertEqual(
            results,
            expected,
        )

    @patch("src.main.scan_host")
    def test_scan_targets_returns_hosts_in_ip_order(
        self,
        mock_scan_host,
    ):
        def fake_scan_host(host, ports, workers):
            return {
                "host": host,
                "responsive": True,
                "open_service_count": 0,
                "open_services": [],
                "results": [],
            }

        mock_scan_host.side_effect = fake_scan_host

        results = scan_targets(
            [
                "127.0.0.2",
                "127.0.0.1",
            ],
            [8000],
            workers=2,
        )

        self.assertEqual(
            [
                result["host"]
                for result in results
            ],
            [
                "127.0.0.1",
                "127.0.0.2",
            ],
        )


class TestJSONExport(unittest.TestCase):
    def test_write_json_creates_valid_report(self):
        results = [
            {
                "port": 443,
                "protocol": "tcp",
                "state": "OPEN",
                "service": "https",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = (
                Path(temp_dir)
                / "reports"
                / "scan.json"
            )

            write_json(
                "127.0.0.1",
                results,
                output_path,
            )

            with output_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

            self.assertEqual(
                data["target"],
                "127.0.0.1",
            )

            self.assertEqual(
                data["results"],
                results,
            )

    def test_write_inventory_json_creates_summary(self):
        host_results = [
            {
                "host": "127.0.0.1",
                "responsive": True,
                "open_service_count": 1,
                "open_services": [
                    {
                        "port": 8000,
                        "protocol": "tcp",
                        "service": "http-alt",
                    }
                ],
                "results": [],
            },
            {
                "host": "127.0.0.2",
                "responsive": False,
                "open_service_count": 0,
                "open_services": [],
                "results": [],
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = (
                Path(temp_dir)
                / "reports"
                / "inventory.json"
            )

            write_inventory_json(
                "127.0.0.0/30",
                host_results,
                output_path,
            )

            with output_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

            self.assertEqual(
                data["target"],
                "127.0.0.0/30",
            )

            self.assertEqual(
                data["summary"]["hosts_scanned"],
                2,
            )

            self.assertEqual(
                data["summary"]["responsive_hosts"],
                1,
            )

            self.assertEqual(
                data["summary"]["open_tcp_services"],
                1,
            )

            self.assertEqual(
                data["hosts"],
                host_results,
            )


if __name__ == "__main__":
    unittest.main()
