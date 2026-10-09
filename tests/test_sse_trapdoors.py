import unittest
import os
import shutil
import tempfile
from crypto_engine import CryptoEngine
from sse_index import SSEIndex, normalize_word, tokenize

class TestSSETrapdoors(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.key_file = os.path.join(self.temp_dir, "master.key")
        self.index_file = os.path.join(self.temp_dir, "search_index.json")
        
        self.crypto = CryptoEngine(key_file=self.key_file)
        self.index = SSEIndex(
            k_idx=self.crypto.k_idx,
            k_tok=self.crypto.k_tok,
            k_blind=self.crypto.k_blind,
            index_file=self.index_file
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_normalization(self):
        self.assertEqual(normalize_word("TAX!"), "tax")
        self.assertEqual(normalize_word("   Invoice,  "), "invoice")
        self.assertEqual(normalize_word("GST-900"), "gst900")

    def test_trapdoor_properties(self):
        # Same keyword gives identical trapdoors
        t1 = self.index.compute_trapdoor("invoice")
        t2 = self.index.compute_trapdoor("invoice")
        self.assertEqual(t1, t2)

        # Normalization consistency
        t3 = self.index.compute_trapdoor("INVOICE!")
        self.assertEqual(t1, t3)

        # Different keywords give different trapdoors
        t_tax = self.index.compute_trapdoor("tax")
        self.assertNotEqual(t1, t_tax)

    def test_index_label_and_posting_encryption(self):
        doc_id = "doc_alpha_1"
        trapdoor = self.index.compute_trapdoor("invoice")
        
        # Label generation with counters
        l0 = self.index.compute_index_label(trapdoor, counter=0)
        l1 = self.index.compute_index_label(trapdoor, counter=1)
        self.assertNotEqual(l0, l1)

        # Encrypt posting and decrypt posting
        enc_posting = self.index.encrypt_posting(trapdoor, doc_id, l0)
        decrypted_doc_id = self.index.decrypt_posting(trapdoor, enc_posting, l0)
        self.assertEqual(decrypted_doc_id, doc_id)

    def test_add_and_search_keyword(self):
        self.index.add_document("doc_1", "Financial tax invoice for client Acme")
        self.index.add_document("doc_2", "Tax audit records and draft notes")

        matching_tax, labels_tax = self.index.search_keyword("tax")
        self.assertEqual(matching_tax, {"doc_1", "doc_2"})
        self.assertEqual(len(labels_tax), 2)

        matching_acme, _ = self.index.search_keyword("acme")
        self.assertEqual(matching_acme, {"doc_1"})

        matching_nonexistent, _ = self.index.search_keyword("nonexistent")
        self.assertEqual(matching_nonexistent, set())


if __name__ == '__main__':
    unittest.main()
