import unittest
import re
from keeper import match_config
from keeper import resolve_ip
from keeper import discover_my_ip


class TestConfRegex(unittest.TestCase):

    def test_matches(self):
        # List of strings that should match
        matches = [
            "_wildcard.example.com.conf",
            "example.com.conf",
            "_wildcard.test-site.com.conf",
            "test.example-site.com.conf",
            "_wildcard.sub.test.com.conf",
            "sub.test.com.conf"
        ]

        for match in matches:
            with self.subTest(match=match):
                self.assertTrue(match_config(match))

    def test_non_matches(self):
        # List of strings that should not match
        non_matches = [
            "example.com",
            "_wildcard.example.com",
            "_wildcardexample.com.conf",
            "example_com.conf",
            "example.com.conf."
        ]

        for non_match in non_matches:
            with self.subTest(non_match=non_match):
                self.assertFalse(match_config(non_match))


class TestResolveIP(unittest.TestCase):

    def test_resolve(self):
        # List of strings that should match
        domains = [
            "google.com",
            "apple.com",
        ]

        for domain in domains:
            with self.subTest(should_resolve=domain):
                self.assertTrue(resolve_ip(domain))

    def test_not_resolve(self):
        # List of strings that should match
        domains = [
            "this-doma1n-sh0uld-n0t-res0lve-pl3333ase.com",
            "this-doma1n-sh0uld-n0t-res0lve-pl3333ase.net",
            "test.non-existing-gtld"
        ]

        for domain in domains:
            with self.subTest(should_not_resolve=domain):
                self.assertFalse(resolve_ip(domain))


class TestDiscoverMyIP(unittest.TestCase):

    def test_ipv4_or_unknown(self):
        ip = discover_my_ip()
        ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        self.assertTrue(ipv4_pattern.match(ip) or ip == "unknown")

    def test_cache(self):
        ip1 = discover_my_ip()
        ip2 = discover_my_ip()
        self.assertEqual(ip1, ip2)


if __name__ == '__main__':
    unittest.main()
