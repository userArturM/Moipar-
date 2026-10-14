import io
import json
import struct
import unittest
from browser_host import handle, matching_records, read_message, verified_origin, write_message

class BrowserBridgeTests(unittest.TestCase):
    def test_native_protocol_roundtrip(self):
        dst = io.BytesIO()
        write_message(dst, {'action':'get_credentials','url':'https://example.org/login'})
        dst.seek(0)
        self.assertEqual(read_message(dst)['action'], 'get_credentials')

    def test_native_protocol_rejects_oversize(self):
        with self.assertRaises(ValueError):
            read_message(io.BytesIO(struct.pack('<I', 65537)))

    def test_https_only(self):
        for value in ['http://example.com', 'file:///vault', 'https://localhost',
                      'https://user:password@example.com', 'https://example.com:4443']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                verified_origin(value)

    def test_exact_hostname_match(self):
        entries = [
            {'url':'https://example.com/login','login':'right','password':'one'},
            {'url':'https://evil-example.com/login','login':'wrong','password':'two'},
            {'url':'https://sub.example.com/login','login':'sub','password':'three'},
            {'url':'https://example.com/','login':'deleted','password':'four','deleted':True},
        ]
        self.assertEqual([e['login'] for e in matching_records(entries,'example.com')], ['right'])

    def test_explicit_selector_receives_checked_domain(self):
        self.assertEqual(handle({'action':'get_credentials','url':'https://example.com/a'},
                                lambda host: {'ok':True,'host':host})['host'], 'example.com')
        self.assertFalse(handle({'action':'unknown','url':'https://example.com'}).get('ok'))

if __name__ == '__main__':
    unittest.main()


class AdditionalBrowserTests(unittest.TestCase):
    def test_no_partial_domain_matches(self):
        from browser_host import matching_records
        rows = [{'url': 'https://good.example.com', 'password': 'x'},
                {'url': 'https://good.example.com.evil.test', 'password': 'y'}]
        self.assertEqual(len(matching_records(rows, 'good.example.com')), 1)

    def test_reject_credentials_in_origin(self):
        from browser_host import verified_origin
        with self.assertRaises(ValueError):
            verified_origin('https://name:secret@example.com/')

