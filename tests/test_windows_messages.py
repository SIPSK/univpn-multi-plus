"""Offline ABI bytes for the independently traced Windows FirstConnect."""
import struct
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import windows_messages as wire


class FirstConnectTests(unittest.TestCase):
    def test_minimal_domain_endpoint_contains_one_explicit_site_in_native_order(self):
        frame = wire.first_connect_endpoint('vpn.fixture.test:49999')
        message = wire.decode_frame(frame)
        self.assertEqual(frame[:24], struct.pack('!6I', 2, 4, 1, 1, 4, 0x9d0))
        expected = bytearray(0x9d0)
        expected[4:4 + 23] = b'vpn.fixture.test:49999\0'
        expected[0x108:0x108 + 17] = b'vpn.fixture.test\0'
        expected[0x188:0x18c] = b'\x4f\xc3\x00\x00'
        expected[0x9c8:0x9cc] = b'\x01\x00\x00\x00'
        self.assertEqual(message.payload, bytes(expected))

    def test_ipv4_port_and_locale_do_not_change_site_selection_or_initial_flags(self):
        message = wire.decode_frame(wire.first_connect_endpoint('192.0.2.1:41024', locale=1))
        body = message.payload
        self.assertEqual(struct.unpack_from('<I', body, 0), (1,))
        self.assertEqual(body[0x108:0x188].split(b'\0', 1)[0], b'192.0.2.1')
        self.assertEqual(struct.unpack_from('<III', body, 0x188), (41024, 0, 0))
        self.assertEqual(struct.unpack_from('<I', body, 0x104), (0,))
        self.assertEqual(struct.unpack_from('<Ii', body, 0x9c8), (1, 0))

    def test_minimal_endpoint_requires_explicit_supported_host_port_shape(self):
        for value in ('vpn.fixture.test', 'vpn.fixture.test:0', 'vpn.fixture.test:65536',
                      'vpn.fixture.test:no-port', 'https://vpn.fixture.test:443',
                      ':443', '[::1]:443', 'vpn.fixture.test:４４３', None):
            with self.subTest(kind=type(value).__name__), self.assertRaises(wire.CodecError):
                wire.first_connect_endpoint(value)


if __name__ == '__main__':
    unittest.main()
