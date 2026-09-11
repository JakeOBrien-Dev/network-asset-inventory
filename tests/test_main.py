import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.main import (
    get_service_name,
    scan_ports,
    validate_ipv4,
    validate_ports,
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


class TestServiceNames(unittest.TestCase):
    def test_known_service(self):
        self.assertEqual(get_service_name(443), "https")

    def test_unknown_service(self):
        self.assertEqual(get_service_name(54321), "unknown")


class TestScanResults(unittest.TestCase):
    @patch("src.main.check_port")
    def test_scan_ports_returns_structured_results(self, mock_check_port):
        mock_check_port.side_effect = ["OPEN", "CLOSED"]

        results = scan_ports("127.0.0.1", [8000, 8001])

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

        self.assertEqual(results, expected)


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
            output_path = Path(temp_dir) / "reports" / "scan.json"

            write_json(
                "127.0.0.1",
                results,
                output_path,
            )

            with output_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            self.assertEqual(data["target"], "127.0.0.1")
            self.assertEqual(data["results"], results)


if __name__ == "__main__":
    unittest.main()
