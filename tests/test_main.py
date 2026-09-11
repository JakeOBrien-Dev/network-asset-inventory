import argparse
import unittest

from src.main import get_service_name, validate_ipv4, validate_ports


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


if __name__ == "__main__":
    unittest.main()
