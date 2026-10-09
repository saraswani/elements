import unittest
import os
import shutil
import tempfile
from cryptography.exceptions import InvalidTag
from crypto_engine import CryptoEngine, load_or_generate_master_key

class TestCryptoEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.key_file = os.path.join(self.temp_dir, "master.key")
        self.crypto = CryptoEngine(key_file=self.key_file)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_key_generation_and_hkdf_derivation(self):
        self.assertTrue(os.path.exists(self.key_file))
        self.assertEqual(len(self.crypto.master_key), 32)
        self.assertEqual(len(self.crypto.k_enc), 32)
        self.assertEqual(len(self.crypto.k_idx), 32)
        self.assertEqual(len(self.crypto.k_tok), 32)
        
        # Verify subkeys are distinct
        self.assertNotEqual(self.crypto.k_enc, self.crypto.k_idx)
        self.assertNotEqual(self.crypto.k_enc, self.crypto.k_tok)
        self.assertNotEqual(self.crypto.k_idx, self.crypto.k_tok)

    def test_encrypt_decrypt_round_trip(self):
        doc_id = "doc_test_1001"
        plaintext = b"Sensitive Q3 financial report containing tax and GST records."
        
        blob = self.crypto.encrypt_document(doc_id, plaintext)
        self.assertTrue(len(blob) > len(plaintext))

        decrypted = self.crypto.decrypt_document(doc_id, blob)
        self.assertEqual(decrypted, plaintext)

    def test_tampered_blob_fails_verification(self):
        doc_id = "doc_test_1002"
        plaintext = b"Top secret corporate merger strategy document."
        
        blob = bytearray(self.crypto.encrypt_document(doc_id, plaintext))
        
        # Tamper with 1 byte in the ciphertext payload
        blob[15] ^= 0xFF

        with self.assertRaises(InvalidTag):
            self.crypto.decrypt_document(doc_id, bytes(blob))

        # Verify through verification helper method
        res = self.crypto.verify_document_blob(doc_id, bytes(blob))
        self.assertFalse(res["valid"])
        self.assertFalse(res["tag_verified"])

    def test_mismatched_doc_id_aad_fails(self):
        doc_id_1 = "doc_test_1003"
        doc_id_2 = "doc_test_1004"
        plaintext = b"Document for user A."

        blob = self.crypto.encrypt_document(doc_id_1, plaintext)

        # Attempting to decrypt blob with wrong doc_id (swapped AAD) must fail
        with self.assertRaises(InvalidTag):
            self.crypto.decrypt_document(doc_id_2, blob)


if __name__ == '__main__':
    unittest.main()
