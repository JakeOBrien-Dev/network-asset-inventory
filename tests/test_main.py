import argparse
import csv
import errno
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.main import (
    MAX_PORTS_PER_SCAN,
    build_host_inventory,
    build_inventory_report,
    build_inventory_summary,
    check_port,
    expand_targets,
    get_service_name,
    get_utc_timestamp,
    run,
    scan_ports,
    scan_targets,
    validate_ipv4,
    validate_port_range,
    validate_ports,
    validate_target,
    validate_workers,
    write_inventory_csv,
    write_report_json,
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
            validate_target("10.0.0.0/8")


class TestTargetExpansion(unittest.TestCase):
    def test_single_target_expansion(self):
        result = expand_targets("127.0.0.1")
        self.assertEqual(
            result,
            ["127.0.0.1"],
        )

    def test_subnet_target_expansion(self):
        result = expand_targets("127.0.0.0/30")

        self.assertEqual(
            result,
            [
                "127.0.0.1",
                "127.0.0.2",
            ],
        )

    def test_point_to_point_subnet_expansion(self):
        result = expand_targets("192.0.2.0/31")

        self.assertEqual(
            result,
            [
                "192.0.2.0",
                "192.0.2.1",
            ],
        )


class TestPortValidation(unittest.TestCase):
    def test_valid_ports(self):
        result = validate_ports("22,80,443")

        self.assertEqual(
            result,
            [22, 80, 443],
        )

    def test_non_numeric_port(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ports("22,banana,443")

    def test_port_too_high(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ports("70000")

    def test_port_zero(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ports("0")

    def test_whitespace_and_duplicate_ports(self):
        result = validate_ports(
            "8000, 8000, 8001"
        )

        self.assertEqual(
            result,
            [8000, 8001],
        )

    def test_empty_port_entry_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ports("80,,443")

    def test_too_many_explicit_ports_rejected(self):
        value = ",".join(
            str(port)
            for port in range(
                1,
                MAX_PORTS_PER_SCAN + 2,
            )
        )

        with self.assertRaises(argparse.ArgumentTypeError):
            validate_ports(value)


class TestPortRangeValidation(unittest.TestCase):
    def test_valid_port_range(self):
        result = validate_port_range(
            "20-25"
        )

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
            validate_port_range(
                "65000-70000"
            )

    def test_too_many_ports_in_range_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_port_range(
                "1-5000"
            )


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
    def test_eagain_is_filtered_or_unreachable(
        self,
        mock_socket,
    ):
        mock_sock = MagicMock()

        mock_socket.return_value.__enter__.return_value = (
            mock_sock
        )

        mock_sock.connect_ex.return_value = (
            errno.EAGAIN
        )

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
            }
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
        def fake_check_port(target, port):
            states = {
                8000: "OPEN",
                8001: "CLOSED",
            }

            return states[port]

        mock_check_port.side_effect = (
            fake_check_port
        )

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

    def test_scan_ports_handles_empty_port_list(self):
        results = scan_ports(
            "127.0.0.1",
            [],
            workers=2,
        )

        self.assertEqual(
            results,
            [],
        )

    @patch(
        "src.main.check_port",
        return_value="CLOSED",
    )
    def test_scan_targets_returns_hosts_in_ip_order(
        self,
        mock_check_port,
    ):
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

    def test_scan_targets_uses_single_bounded_pool(self):
        with patch(
            "src.main.check_port",
            return_value="CLOSED",
        ):
            with patch(
                "src.main.ThreadPoolExecutor",
                wraps=ThreadPoolExecutor,
            ) as mock_executor:

                scan_targets(
                    [
                        "127.0.0.1",
                        "127.0.0.2",
                    ],
                    [
                        8000,
                        8001,
                    ],
                    workers=3,
                )

        mock_executor.assert_called_once_with(
            max_workers=3
        )


class TestReporting(unittest.TestCase):
    def setUp(self):
        self.host_results = [
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

    def test_inventory_summary(self):
        summary = build_inventory_summary(
            self.host_results
        )

        self.assertEqual(
            summary,
            {
                "hosts_scanned": 2,
                "responsive_hosts": 1,
                "unresponsive_hosts": 1,
                "hosts_with_open_services": 1,
                "open_tcp_services": 1,
            },
        )

    @patch(
        "src.main.get_utc_timestamp",
        return_value=(
            "2026-09-11T22:55:31+00:00"
        ),
    )
    def test_inventory_report_contains_timestamp(
        self,
        mock_timestamp,
    ):
        report = build_inventory_report(
            "127.0.0.0/30",
            self.host_results,
        )

        self.assertEqual(
            report["target"],
            "127.0.0.0/30",
        )

        self.assertEqual(
            report["scanned_at"],
            "2026-09-11T22:55:31+00:00",
        )

        self.assertEqual(
            report["hosts"],
            self.host_results,
        )

    def test_utc_timestamp_uses_utc(self):
        timestamp = get_utc_timestamp()

        parsed = datetime.fromisoformat(
            timestamp
        )

        self.assertEqual(
            parsed.utcoffset(),
            timedelta(0),
        )

    def test_write_report_json(self):
        report = {
            "target": "127.0.0.0/30",
            "scanned_at": (
                "2026-09-11T22:55:31+00:00"
            ),
            "summary": {
                "hosts_scanned": 2,
                "responsive_hosts": 1,
                "unresponsive_hosts": 1,
                "hosts_with_open_services": 1,
                "open_tcp_services": 1,
            },
            "hosts": self.host_results,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = (
                Path(temp_dir)
                / "reports"
                / "inventory.json"
            )

            write_report_json(
                report,
                output_path,
            )

            with output_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

            self.assertEqual(
                data,
                report,
            )

    def test_write_inventory_csv(self):
        report = {
            "target": "127.0.0.0/30",
            "scanned_at": (
                "2026-09-11T22:55:31+00:00"
            ),
            "summary": {},
            "hosts": self.host_results,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = (
                Path(temp_dir)
                / "reports"
                / "inventory.csv"
            )

            write_inventory_csv(
                report,
                output_path,
            )

            with output_path.open(
                "r",
                encoding="utf-8",
                newline="",
            ) as file:
                rows = list(
                    csv.DictReader(file)
                )

            self.assertEqual(
                len(rows),
                2,
            )

            self.assertEqual(
                rows[0]["host"],
                "127.0.0.1",
            )

            self.assertEqual(
                rows[0]["port"],
                "8000",
            )

            self.assertEqual(
                rows[1]["host"],
                "127.0.0.2",
            )

            self.assertEqual(
                rows[1]["port"],
                "",
            )


class TestRuntimeHardening(unittest.TestCase):
    @patch("src.main.scan_host")
    @patch("src.main.parse_arguments")
    def test_keyboard_interrupt_returns_130(
        self,
        mock_parse_arguments,
        mock_scan_host,
    ):
        mock_parse_arguments.return_value = (
            argparse.Namespace(
                target="127.0.0.1",
                ports=[8000],
                port_range=None,
                workers=2,
                json_output=None,
                csv_output=None,
            )
        )

        mock_scan_host.side_effect = (
            KeyboardInterrupt
        )

        result = run()

        self.assertEqual(
            result,
            130,
        )

    @patch(
        "src.main.write_report_json",
        side_effect=OSError(
            "disk full"
        ),
    )
    @patch("src.main.display_inventory")
    @patch("src.main.scan_host")
    @patch("src.main.parse_arguments")
    def test_report_write_error_returns_one(
        self,
        mock_parse_arguments,
        mock_scan_host,
        mock_display_inventory,
        mock_write_report_json,
    ):
        mock_parse_arguments.return_value = (
            argparse.Namespace(
                target="127.0.0.1",
                ports=[8000],
                port_range=None,
                workers=2,
                json_output="output/report.json",
                csv_output=None,
            )
        )

        mock_scan_host.return_value = {
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
        }

        result = run()

        self.assertEqual(
            result,
            1,
        )


if __name__ == "__main__":
    unittest.main()
