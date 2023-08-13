import unittest
from otp_gen import *

class TestTruncate(unittest.TestCase):
    def testTruncateWorks(self):
        test_hex_str = '1f 86 98 69 0e 02 ca 16 61 85 50 ef 7f 19 da 8e 94 5b 55 5a'
        test_bytes = bytes.fromhex(test_hex_str)
        otp = truncate(test_bytes)
        self.assertEqual(otp, 872921)

        test_hex_str = 'a9 4a 8f e5 cc b1 9b a6 1c 4c 08 73 d3 91 e9 87 98 2f bb d3'
        test_bytes = bytes.fromhex(test_hex_str)
        otp = truncate(test_bytes)
        self.assertEqual(otp, 913627)


