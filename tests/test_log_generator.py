# Unit tests for log_generator.utils
import re
import unittest
from ..utils import ip, ua, path, http_method, status, referrer, timestamp, generate_access_log_entry
from ..data import good_paths, bad_paths, ua_pct

class TestUtils(unittest.TestCase):
    def test_ip(self):
        # Test that the ip function returns a string
        self.assertIsInstance(ip(), str)

        # Test that the ip function returns a valid IP address
        self.assertTrue(ip().count('.') == 3)
        self.assertTrue(all(0 <= int(octet) <= 255 for octet in ip().split('.')))

    def test_ua(self):
        # Test that the ua function returns a string
        self.assertIsInstance(ua(ua_pct), str)

    def test_path(self):
        # Test that the path function returns a string
        self.assertIsInstance(path(good_paths,bad_paths), str)

        # Test that the path function returns a valid path
        self.assertTrue(path(good_paths,bad_paths).startswith('/'))

    def test_http_method(self):
        # Test that the http_method function returns a string
        self.assertIsInstance(http_method(), str)

        # Test that the http_method function returns a valid HTTP method
        self.assertTrue(http_method() in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'])

    def test_status(self):
        # Test that the status function returns a string
        self.assertIsInstance(status(good_paths,request=""), str)

        # Test that the status function returns a valid status code
        self.assertTrue(status(good_paths,request="") in ['200', '400', '401', '403', '404', '500', '503'])

    def test_referrer(self):
        # Test that the referrer function returns a string
        self.assertIsInstance(referrer(), str)

    def test_timestamp(self):
        # Test that the timestamp function returns a string
        self.assertIsInstance(timestamp(), str)

        # Test that the timestamp function returns a valid timestamp
        self.assertTrue(re.match(r'\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} [-+]\d{4}', timestamp()))

    def test_generate_access_log_entry(self):
        # Test that the generate_access_log_entry function returns a string
        self.assertIsInstance(generate_access_log_entry(good_paths,bad_paths,ua_pct), str)

        # Test that the generate_access_log_entry function returns a valid access log entry
        log_regex = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*)\] "(?P<method>\w+) (?P<path>/.*) (?P<protocol>HTTP/\d\.\d)" (?P<status>\d{3}) (?P<bytes>\d+) (?P<referrer>.*) "(?P<user_agent>.*)"'
        self.assertTrue(re.match(log_regex, generate_access_log_entry(good_paths,bad_paths,ua_pct)))

if __name__ == '__main__':
    unittest.main()
