import os
import json
import hmac
import hashlib
import string
import secrets
from typing import List, Set, Dict, Tuple, Optional
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
    "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself",
    "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought",
    "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she",
    "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such",
    "than", "that", "that's", "the", "their", "theirs", "them", "themselves",
    "then", "there", "there's", "these", "they", "they'd", "they'll", "they're",
    "they've", "this", "those", "through", "to", "too", "under", "until", "up",
    "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were",
    "weren't", "what", "what's", "when", "when's", "where", "where's", "which",
    "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would",
    "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours",
    "yourself", "yourselves"
}

INDEX_FILE = "search_index.json"

def normalize_word(word: str) -> str:
    """Converts word to lowercase and strips punctuation."""
    table = str.maketrans('', '', string.punctuation)
    return word.translate(table).lower().strip()

def tokenize(text: str, include_stopwords: bool = False) -> Set[str]:
    """Tokenizes raw text into normalized, unique keywords, removing stop words."""
    raw_tokens = text.split()
    tokens = set()
    for raw in raw_tokens:
        clean = normalize_word(raw)
        if clean:
            if include_stopwords or clean not in STOP_WORDS:
                tokens.add(clean)
    return tokens

# Optional Stretch Goal: N-Gram tokenization for prefix search
def tokenize_ngrams(text: str, min_n: int = 3, max_n: int = 5) -> Set[str]:
    """
    [STRETCH GOAL - OPTIONAL]
    Generates n-grams for prefix/substring matching.
    Clearly marked stretch goal as n-gram indexing leaks more token co-occurrence patterns.
    """
    tokens = tokenize(text, include_stopwords=False)
    ngrams = set(tokens)
    for token in tokens:
        for n in range(min_n, min(max_n + 1, len(token) + 1)):
            for i in range(len(token) - n + 1):
                ngrams.add(token[i:i+n])
    return ngrams


class SSEIndex:
    """
    Searchable Symmetric Encryption (SSE) Inverted Index using HMAC trapdoors
    and per-keyword AES-GCM encrypted postings.
    """

    def __init__(self, k_idx: bytes, k_tok: bytes, k_blind: bytes, index_file: str = INDEX_FILE):
        self.k_idx = k_idx
        self.k_tok = k_tok
        self.k_blind = k_blind
        self.index_file = index_file
        self.data = self._load_index()

    def _load_index(self) -> dict:
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"labels": {}, "keyword_counters": {}, "blind_index": {}}

    def save(self):
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def compute_trapdoor(self, word: str) -> bytes:
        """T = HMAC-SHA256(K_tok, normalized_word)"""
        clean_word = normalize_word(word)
        return hmac.new(self.k_tok, clean_word.encode("utf-8"), hashlib.sha256).digest()

    def _derive_posting_key(self, trapdoor: bytes) -> bytes:
        """Derives per-keyword AES-256 key from trapdoor T using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"posting_key",
        )
        return hkdf.derive(trapdoor)

    def compute_index_label(self, trapdoor: bytes, counter: int) -> str:
        """
        L = HMAC-SHA256(K_idx, T || counter)
        Returns hex string of the label.
        """
        msg = trapdoor + counter.to_bytes(4, byteorder="big")
        return hmac.new(self.k_idx, msg, hashlib.sha256).hexdigest()

    def encrypt_posting(self, trapdoor: bytes, doc_id: str, label_hex: str) -> str:
        """Encrypts doc_id under per-keyword key derived from T."""
        posting_key = self._derive_posting_key(trapdoor)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(posting_key)
        aad = label_hex.encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, doc_id.encode("utf-8"), aad)
        return (nonce + ciphertext).hex()

    def decrypt_posting(self, trapdoor: bytes, encrypted_posting_hex: str, label_hex: str) -> Optional[str]:
        """Decrypts encrypted posting to recover document ID."""
        try:
            posting_key = self._derive_posting_key(trapdoor)
            blob = bytes.fromhex(encrypted_posting_hex)
            if len(blob) < 12 + 16:
                return None
            nonce = blob[:12]
            ciphertext = blob[12:]
            aesgcm = AESGCM(posting_key)
            aad = label_hex.encode("utf-8")
            doc_id_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
            return doc_id_bytes.decode("utf-8")
        except (InvalidTag, ValueError):
            return None

    def add_document(self, doc_id: str, text: str, structured_fields: Optional[dict] = None) -> List[str]:
        """
        Indexes a document under all normalized tokens.
        Returns list of generated index labels (hex).
        """
        tokens = tokenize(text)
        labels_generated = []

        for token in tokens:
            trapdoor = self.compute_trapdoor(token)
            t_hex = trapdoor.hex()

            # Retrieve current counter for this keyword
            counter = self.data["keyword_counters"].get(t_hex, 0)
            label_hex = self.compute_index_label(trapdoor, counter)

            encrypted_posting = self.encrypt_posting(trapdoor, doc_id, label_hex)

            self.data["labels"][label_hex] = encrypted_posting
            self.data["keyword_counters"][t_hex] = counter + 1
            labels_generated.append(label_hex)

        # Blind index for structured fields (e.g., customer_id, category)
        if structured_fields:
            for field_name, value in structured_fields.items():
                if value:
                    field_tag = self.compute_blind_tag(field_name, str(value))
                    field_trapdoor = hmac.new(self.k_tok, field_tag.encode("utf-8"), hashlib.sha256).digest()
                    field_counter = self.data["keyword_counters"].get(field_tag, 0)
                    field_label = self.compute_index_label(field_trapdoor, field_counter)
                    enc_post = self.encrypt_posting(field_trapdoor, doc_id, field_label)
                    self.data["labels"][field_label] = enc_post
                    self.data["keyword_counters"][field_tag] = field_counter + 1
                    labels_generated.append(field_label)

        self.save()
        return labels_generated

    def compute_blind_tag(self, field_name: str, value: str) -> str:
        """Blind index tag for exact-match structured query."""
        msg = f"{field_name}:{normalize_word(value)}".encode("utf-8")
        return hmac.new(self.k_blind, msg, hashlib.sha256).hexdigest()

    def search_trapdoor(self, trapdoor: bytes) -> Tuple[Set[str], List[str]]:
        """
        Given keyword trapdoor T, probes L_0, L_1, ... until label is not found in index.
        Returns tuple of (set_of_doc_ids, list_of_queried_labels_hex).
        """
        matching_doc_ids = set()
        queried_labels = []
        counter = 0

        while True:
            label_hex = self.compute_index_label(trapdoor, counter)
            if label_hex not in self.data["labels"]:
                break
            queried_labels.append(label_hex)
            enc_posting = self.data["labels"][label_hex]
            doc_id = self.decrypt_posting(trapdoor, enc_posting, label_hex)
            if doc_id:
                matching_doc_ids.add(doc_id)
            counter += 1

        return matching_doc_ids, queried_labels

    def search_keyword(self, word: str) -> Tuple[Set[str], List[str]]:
        """Performs SSE search for a single normalized keyword."""
        clean = normalize_word(word)
        if not clean:
            return set(), []
        trapdoor = self.compute_trapdoor(clean)
        return self.search_trapdoor(trapdoor)

    def search_blind_field(self, field_name: str, value: str) -> Tuple[Set[str], List[str]]:
        """Performs blind index lookup for structured field exact match."""
        field_tag = self.compute_blind_tag(field_name, value)
        field_trapdoor = hmac.new(self.k_tok, field_tag.encode("utf-8"), hashlib.sha256).digest()
        return self.search_trapdoor(field_trapdoor)

    def verify_index_entry(self, doc_id: str, text: str) -> dict:
        """
        Verifies that all tokens in the document exist in search_index.json
        and decrypt correctly to doc_id.
        """
        tokens = tokenize(text)
        missing_tokens = []
        verified_count = 0

        for token in tokens:
            trapdoor = self.compute_trapdoor(token)
            doc_ids, _ = self.search_trapdoor(trapdoor)
            if doc_id in doc_ids:
                verified_count += 1
            else:
                missing_tokens.append(token)

        return {
            "verified": len(missing_tokens) == 0,
            "total_tokens": len(tokens),
            "verified_tokens": verified_count,
            "missing_tokens": missing_tokens
        }
