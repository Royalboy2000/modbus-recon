# modbus_scanner/tests/test_network_utils.py
import unittest
import ipaddress
from modbus_scanner.utils.network_utils import parse_ip_targets

class TestNetworkUtils(unittest.TestCase):

    def test_parse_ip_targets_single_ip(self):
        self.assertEqual(parse_ip_targets("192.168.1.1"), ["192.168.1.1"])
        self.assertEqual(parse_ip_targets("2001:db8::1"), ["2001:db8::1"])

    def test_parse_ip_targets_simple_range_v4(self):
        self.assertEqual(parse_ip_targets("192.168.1.1-3"), ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_parse_ip_targets_full_ip_range_v4(self):
        self.assertEqual(parse_ip_targets("192.168.1.1-192.168.1.3"), ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_parse_ip_targets_suffix_range_v4(self):
        self.assertEqual(parse_ip_targets("192.168.1.10-12"), ["192.168.1.10", "192.168.1.11", "192.168.1.12"])

    def test_parse_ip_targets_invalid_range_suffix_order_v4(self):
        self.assertEqual(parse_ip_targets("192.168.1.10-5"), []) # Start octet > end octet

    def test_parse_ip_targets_invalid_range_full_ip_order_v4(self):
        self.assertEqual(parse_ip_targets("192.168.1.10-192.168.1.1"), []) # Start IP > end IP

    def test_parse_ip_targets_cidr_v4(self):
        self.assertEqual(parse_ip_targets("192.168.1.0/30"), ["192.168.1.1", "192.168.1.2"])

    def test_parse_ip_targets_single_host_cidr_v4(self):
        self.assertEqual(parse_ip_targets("192.168.1.1/32"), ["192.168.1.1"])

    def test_parse_ip_targets_large_cidr_v4(self):
        # Test a /24 which should yield 254 host addresses
        # ipaddress.ip_network('192.168.1.0/24').hosts()
        expected_ips = [f"192.168.1.{i}" for i in range(1, 255)] # Corrected range
        result = parse_ip_targets("192.168.1.0/24") # Changed from 192.168.1.1/24
        self.assertEqual(len(result), 254)
        self.assertEqual(result[0], "192.168.1.1")
        self.assertEqual(result[-1], "192.168.1.254")


    def test_parse_ip_targets_full_ip_range_v6(self):
        self.assertEqual(parse_ip_targets("2001:db8::1-2001:db8::3"), ["2001:db8::1", "2001:db8::2", "2001:db8::3"])

    def test_parse_ip_targets_cidr_v6(self):
        # For '2001:db8::/126', ipaddress.ip_network().hosts() yields ::1, ::2, ::3
        # Network address: 2001:db8::0
        # Highest address in subnet (Subnet-Router anycast): 2001:db8::3
        self.assertEqual(parse_ip_targets("2001:db8::/126"), ["2001:db8::1", "2001:db8::2", "2001:db8::3"])

    def test_parse_ip_targets_single_host_cidr_v6(self):
        self.assertEqual(parse_ip_targets("2001:db8::1/128"), ["2001:db8::1"])

    def test_parse_ip_targets_comma_separated(self):
        expected = sorted([
            "10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.7",
            "10.0.1.1", "10.0.1.2"
        ], key=ipaddress.ip_address)
        self.assertEqual(parse_ip_targets("10.0.0.1,10.0.0.5-7,10.0.1.0/30"), expected)

    def test_parse_ip_targets_with_spaces(self):
        expected = sorted(["192.168.5.5", "192.168.5.10", "192.168.5.11", "192.168.5.12"], key=ipaddress.ip_address)
        self.assertEqual(parse_ip_targets("  192.168.5.5  , 192.168.5.10-12 "), expected)

    def test_parse_ip_targets_duplicates(self):
        self.assertEqual(parse_ip_targets("192.168.1.1, 192.168.1.1, 192.168.1.2"), ["192.168.1.1", "192.168.1.2"])

    def test_parse_ip_targets_invalid_parts(self):
        self.assertEqual(parse_ip_targets("invalid-ip,192.168.1.1"), ["192.168.1.1"])
        self.assertEqual(parse_ip_targets("192.168.1.1-192.168.2.bad"), []) # Entire invalid range part is skipped
        self.assertEqual(parse_ip_targets("192.168.1.1-bad"), []) # Entire invalid range part is skipped

    def test_parse_ip_targets_empty_string(self):
        self.assertEqual(parse_ip_targets(""), [])

    def test_parse_ip_targets_comma_only(self):
        self.assertEqual(parse_ip_targets(",,"), [])

    def test_range_across_subnets(self):
        # 192.168.1.1 to 192.168.1.255 (255 IPs)
        # 192.168.2.0 to 192.168.2.1 (2 IPs)
        # Total = 255 + 2 = 257 IPs
        result = parse_ip_targets("192.168.1.1-192.168.2.1")
        self.assertEqual(len(result), 257)
        self.assertEqual(str(result[0]), "192.168.1.1")
        self.assertEqual(str(result[-1]), "192.168.2.1")

if __name__ == '__main__':
    unittest.main()
