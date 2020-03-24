import unittest
from aes import AES

class TestBlock(unittest.TestCase):
    """
    Tests raw AES-128 block operations.
    """
    def setUp(self):
        self.aes = AES(b'\00' * 16)

    def test_success(self):
        """ Should be able to encrypt and decrypt block messages. """
        message = b'\01' * 16
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)

        message = b'a secret message'
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)

    def test_bad_key(self):
        """ Raw AES requires keys of an exact size. """
        with self.assertRaises(AssertionError):
            AES(b'short key')

        with self.assertRaises(AssertionError):
            AES(b'long key' * 10)

    def test_expected_value(self):
        """
        Tests taken from the NIST document, Appendix B:
        http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
        """
        message = b'\x32\x43\xF6\xA8\x88\x5A\x30\x8D\x31\x31\x98\xA2\xE0\x37\x07\x34'
        key     = b'\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C'
        ciphertext = AES(bytes(key)).encrypt_block(bytes(message))
        self.assertEqual(ciphertext, b'\x39\x25\x84\x1D\x02\xDC\x09\xFB\xDC\x11\x85\x97\x19\x6A\x0B\x32')
    def test_expected2_value(self):
        """
        Tests taken from the NIST document, Appendix B:
        http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
        """
        message = b'\x43\x6f\x72\x72\x65\x63\x74\x20\x44\x65\x63\x72\x79\x70\x74\x21'
        key     = b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F'
        ciphertext = AES(bytes(key)).encrypt_block(bytes(message))
        self.assertEqual(ciphertext,  b'\xF4\x35\x15\x03\xAA\x78\x1C\x52\x02\x67\xD6\x90\xC4\x2D\x1F\x43')    
    def test_decrypt_value(self):
        """
        Tests taken from the NIST document, Appendix B:
        http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
        """
        key        = b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F'
        ciphertext = b'\xF4\x35\x15\x03\xAA\x78\x1C\x52\x02\x67\xD6\x90\xC4\x2D\x1F\x43'
        message = AES(bytes(key)).decrypt_block(bytes(ciphertext))
        print("", message)
        self.assertEqual(message, b'\x43\x6f\x72\x72\x65\x63\x74\x20\x44\x65\x63\x72\x79\x70\x74\x21')



def run():
    unittest.main()

if __name__ == '__main__':
    run()