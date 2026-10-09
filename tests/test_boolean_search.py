import unittest
import os
import shutil
import tempfile
import random
from crypto_engine import CryptoEngine
from sse_index import SSEIndex, tokenize
from boolean_parser import evaluate_boolean_query
from storage_provider import LocalStorageProvider

VOCABULARY = [
    "invoice", "tax", "gst", "draft", "report", "audit", "customer", "payment",
    "refund", "vendor", "acme", "payroll", "budget", "quarterly", "final"
]

def generate_random_document(doc_num: int) -> str:
    # Select 4 to 8 random words from VOCABULARY
    k = random.randint(4, 8)
    words = random.sample(VOCABULARY, k)
    return f"Doc_{doc_num}: " + " ".join(words)

class TestBooleanSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        random.seed(42)  # Seed for deterministic reproducible corpus testing

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.key_file = os.path.join(self.temp_dir, "master.key")
        self.index_file = os.path.join(self.temp_dir, "search_index.json")
        self.store_dir = os.path.join(self.temp_dir, "local_store")

        self.crypto = CryptoEngine(key_file=self.key_file)
        self.index = SSEIndex(
            k_idx=self.crypto.k_idx,
            k_tok=self.crypto.k_tok,
            k_blind=self.crypto.k_blind,
            index_file=self.index_file
        )
        self.storage = LocalStorageProvider(store_dir=self.store_dir)

        # Generate corpus of 50 documents
        self.corpus = {}
        for i in range(1, 51):
            doc_id = f"doc_{i:02d}.txt"
            content = generate_random_document(i)
            self.corpus[doc_id] = content
            
            # Encrypt and upload to local store
            blob = self.crypto.encrypt_document(doc_id, content.encode('utf-8'))
            self.storage.upload_bytes(doc_id, blob)

            # Index document
            self.index.add_document(doc_id, content)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _plaintext_baseline_search(self, query_str: str) -> set:
        """Computes ground truth matching doc IDs using naive plaintext scanning."""
        matched_ids = set()
        all_doc_ids = set(self.corpus.keys())

        for doc_id, text in self.corpus.items():
            tokens = tokenize(text)
            
            # Basic parsing rules matching test queries
            if query_str == "invoice AND tax":
                if "invoice" in tokens and "tax" in tokens:
                    matched_ids.add(doc_id)
            elif query_str == "invoice OR budget":
                if "invoice" in tokens or "budget" in tokens:
                    matched_ids.add(doc_id)
            elif query_str == "invoice NOT draft":
                if "invoice" in tokens and "draft" not in tokens:
                    matched_ids.add(doc_id)
            elif query_str == "invoice AND (tax OR gst) NOT draft":
                if "invoice" in tokens and ("tax" in tokens or "gst" in tokens) and "draft" not in tokens:
                    matched_ids.add(doc_id)
            elif query_str == "NOT draft":
                if "draft" not in tokens:
                    matched_ids.add(doc_id)
        return matched_ids

    def test_boolean_queries_against_baseline(self):
        all_doc_ids = set(self.corpus.keys())

        test_queries = [
            "invoice AND tax",
            "invoice OR budget",
            "invoice NOT draft",
            "invoice AND (tax OR gst) NOT draft",
            "NOT draft"
        ]

        for query_str in test_queries:
            def fetch_keyword_docs(keyword: str):
                return self.index.search_keyword(keyword)

            sse_results, queried_labels = evaluate_boolean_query(
                query_str, fetch_keyword_docs, all_doc_ids
            )

            expected_results = self._plaintext_baseline_search(query_str)
            self.assertEqual(
                sse_results,
                expected_results,
                f"Query '{query_str}' failed! SSE returned {sse_results} vs Expected {expected_results}"
            )


if __name__ == '__main__':
    unittest.main()
