# tests/test_hasher.py

import unittest
from ocpp_anonymizer.hasher import hash_value, anonymize_url, SECRET_SALT

class TestHasher(unittest.TestCase):

    def test_hash_value_consistency(self):
        """Verify that the same input always produces the same hash."""
        self.assertEqual(hash_value("test_string"), hash_value("test_string"))

    def test_hash_value_uniqueness(self):
        """Verify that different inputs produce different hashes."""
        self.assertNotEqual(hash_value("test_string_1"), hash_value("test_string_2"))

    def test_hash_value_with_none(self):
        """Verify that None input returns None."""
        self.assertIsNone(hash_value(None))

    def test_anonymize_url_ftp(self):
        """Test that FTP URLs with credentials are stripped."""
        url = "ftp://user:password@example.com/resource"
        self.assertEqual(anonymize_url(url), "ftp://example.com/resource")

    def test_anonymize_url_http(self):
        """Test that HTTP URLs with credentials are stripped."""
        url = "http://user:password@example.com/resource"
        self.assertEqual(anonymize_url(url), "http://example.com/resource")

    def test_anonymize_url_no_credentials(self):
        """Test that URLs without credentials remain unchanged."""
        url = "https://example.com/resource"
        self.assertEqual(anonymize_url(url), url)

    def test_anonymize_url_invalid(self):
        """Test that invalid URLs are handled gracefully."""
        self.assertEqual(anonymize_url("not a url"), "[INVALID_URL_MASKED]")
        self.assertEqual(anonymize_url(123), "[INVALID_URL_MASKED]")

if __name__ == '__main__':
    unittest.main()
