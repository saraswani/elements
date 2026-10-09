import unittest
import os
import shutil
import tempfile
from audit_logger import log_audit_event, read_audit_log
from crypto_engine import CryptoEngine
from sse_index import SSEIndex
from boolean_parser import evaluate_boolean_query

SECRET_TEST_KEYWORDS = ["supersecretkeyword99", "confidentialtaxrecord", "topsecretprojectx"]

class TestAuditLogSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "audit.log")
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

    def test_audit_log_contains_zero_plaintext_keywords(self):
        # 1. Simulate document upload with secret keywords
        doc_id = "doc_audit_test_01.txt"
        doc_content = f"This document contains {SECRET_TEST_KEYWORDS[0]} and {SECRET_TEST_KEYWORDS[1]}"
        
        labels = self.index.add_document(doc_id, doc_content)
        log_audit_event("upload", blob_ids=[doc_id], label_hashes=labels, result_count=1, log_file=self.log_file)

        # 2. Simulate search query with secret keyword
        def fetch_keyword_docs(keyword: str):
            return self.index.search_keyword(keyword)

        matching_ids, queried_labels = evaluate_boolean_query(
            SECRET_TEST_KEYWORDS[0], fetch_keyword_docs, {doc_id}
        )
        log_audit_event("search", blob_ids=list(matching_ids), label_hashes=queried_labels, result_count=len(matching_ids), log_file=self.log_file)

        # 3. Read raw audit log file content and assert zero occurrence of test keywords
        with open(self.log_file, "r", encoding="utf-8") as f:
            raw_log_content = f.read()

        for kw in SECRET_TEST_KEYWORDS:
            self.assertNotIn(kw, raw_log_content, f"SECURITY LEAK FAIL: Keyword '{kw}' found in audit.log!")

        # 4. Verify structured JSON line integrity
        records = read_audit_log(self.log_file)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["operation"], "upload")
        self.assertEqual(records[1]["operation"], "search")


if __name__ == '__main__':
    unittest.main()
