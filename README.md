# Verifiable Searchable Symmetric Encryption (SSE) Engine

A Python web application built for hackathons implementing **Verifiable Searchable Symmetric Encryption (SSE)** over untrusted third-party cloud storage (Google Drive / OneDrive / Local Store). 

Standard end-to-end encryption breaks keyword searchability. This SSE Engine encrypts sensitive documents with **AES-256-GCM** (with Document ID bound as Associated Authenticated Data) and indexes token trapdoors using **HMAC-SHA256** and **HKDF-SHA256**, allowing full boolean keyword search (`AND`, `OR`, `NOT`, `()`) over encrypted cloud ciphertexts **without ever leaking plaintext content, search terms, or raw keywords to the cloud server**.

---

## Key Features

- **Cryptographic Key Derivation**: Master 32-byte key derived via HKDF-SHA256 into dedicated subkeys (`K_enc`, `K_idx`, `K_tok`, `K_blind`).
- **Authenticated Document Encryption**: AES-256-GCM encryption per document with a random 12-byte nonce. Document ID bound as AAD to prevent ciphertext blob swapping.
- **Searchable Symmetric Encryption (SSE) Inverted Index**:
  - Keyword trapdoors: `T = HMAC-SHA256(K_tok, normalized_word)`
  - Index labels: `L = HMAC-SHA256(K_idx, T || counter)`
  - Per-keyword encrypted postings: Document IDs encrypted with AES-256-GCM under keys derived from `T`.
- **Boolean Query Engine**: Lexer, Shunting-Yard RPN parser, and set evaluator supporting complex expressions like `invoice AND (tax OR gst) NOT draft`.
- **Verifiable Proof System**: `/verify/<doc_id>` route validates AES-GCM tag integrity, AAD binding, and index consistency.
- **Blind Indexing**: Fast exact-match lookups for structured metadata fields (e.g. `customer_id`) via `HMAC(K_blind, field:value)`.
- **Cloud Provider Abstraction**: Supports local filesystem storage (`./local_store/`, default), Google Drive API (`drive_client.py`), and OneDrive.
- **Zero-Leakage Audit Logging**: Structured JSON logging (`audit.log`) tracking operations without ever recording plaintext tokens, queries, or secret keys.

---

## Project Structure

```
Elements/
├── app.py                  # Main Flask Web Server & API Routes
├── crypto_engine.py        # Master Key & AES-256-GCM Cryptographic Engine
├── sse_index.py            # SSE Inverted Index & HMAC Trapdoor Engine
├── boolean_parser.py       # Boolean Query Lexer, RPN Parser & Set Evaluator
├── storage_provider.py     # LocalStore & Storage Provider Factory
├── drive_client.py         # Google Drive OAuth & API Client
├── config_manager.py       # Secret Masking & .env Config Persistence
├── audit_logger.py         # Zero-Leakage JSON Audit Logger
├── requirements.txt        # Python Dependencies
├── .gitignore              # Ignores master.key, credentials.json, audit.log, etc.
├── templates/
│   ├── base.html           # Layout & Dark Glassmorphism Navigation
│   ├── index.html          # Portal Dashboard (Upload & Search Engine)
│   ├── server_view.html    # Untrusted Server Inspector & Audit Stream
│   └── setup.html          # Setup & API Key Configuration Page
├── static/
│   └── style.css           # Styling & Animations
└── tests/
    ├── test_crypto.py      # AES-GCM Round-trip & Tamper Verification Tests
    ├── test_sse_trapdoors.py# Trapdoor Determinism & Posting Tests
    ├── test_boolean_search.py# 50-Document Corpus Boolean Search Baseline Tests
    └── test_audit_log.py   # Audit Log Zero-Leakage Security Tests
```

---

## Setup & Installation

### 1. Requirements
- Python 3.10+
- `pip`

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## How to Run the App

Start the server using local storage mode (no Google OAuth login required):

```bash
python app.py
```

Open your browser and navigate to:
[http://127.0.0.1:5000](http://127.0.0.1:5000)

### Key Routes
- **`GET /`**: Main Dashboard — Encrypt & Upload documents, execute Boolean SSE queries, view stored document vault.
- **`GET /server-view`**: Untrusted Server Inspector — Shows raw ciphertext blobs, encrypted index entries, and raw audit logs. Demonstrates zero plaintext exposure.
- **`GET /setup`**: Setup Page — Input API keys, paste/upload Google OAuth `credentials.json`, choose storage provider.
- **`GET /verify/<doc_id>`**: Verifiability Check — Validates AES-GCM tag integrity, AAD document ID binding, and index consistency.
- **`GET /search?q=...`**: Search API endpoint returning JSON search results and execution telemetry.

---

## How to Run Tests

Run the full automated test suite using `unittest`:

```bash
python -m unittest discover -s tests
```

Or run individual test modules:
```bash
python -m unittest tests/test_crypto.py
python -m unittest tests/test_sse_trapdoors.py
python -m unittest tests/test_boolean_search.py
python -m unittest tests/test_audit_log.py
```

*Note: All tests use local storage (`./local_store/`) and execute completely offline without requiring Google login.*

---

## Leakage Table: What the Server Learns vs. Cannot Learn

An honest-but-curious server or untrusted cloud provider sees only encrypted blobs, label hashes, and query traffic.

| Information Category | What the Server LEARNS (Permissible Leakage) | What the Server CANNOT Learn (Protected Security) |
| :--- | :--- | :--- |
| **Document Contents** | Ciphertext size (in bytes), total blob count | Plaintext text, document words, file contents |
| **Access Pattern** | Which encrypted document IDs match a given search query | Plaintext document titles or contents of matched files |
| **Search Pattern** | Whether two search queries are identical (same label hashes) | Plaintext search terms, query keywords, boolean operators |
| **Index Structure** | Total count of indexed posting entries | Plaintext vocabulary, token frequencies, dictionary words |
| **Audit Logs** | Timestamps, operation type (`upload`/`search`), result counts | Raw search queries, secret keys, user credentials |

---

## Stretch Goals List

- **Prefix & Substring N-Gram Indexing** (`[STRETCH GOAL]`): Implemented in `sse_index.py` (`tokenize_ngrams`). *Marked as optional stretch goal because sub-token n-gram indexing increases index size and leaks token co-occurrence frequency patterns.*
- **Blind Index Structured Queries**: Implemented in `sse_index.py` (`compute_blind_tag`). Enables fast exact-match metadata filtering (e.g. `customer_id: CUST-9921`) without exposing field names or values.
- **OneDrive Provider Interface**: Provider interface stub implemented in `storage_provider.py` (`OneDriveStorageProvider`), ready for Microsoft Graph API integration.

---

## Summary of Server Visibility

### What the Server CAN See:
1. **Raw Blob Storage**: Encrypted byte blobs stored in cloud storage (Google Drive / `./local_store/`). The server sees random hex bytes, blob sizes, and timestamp metadata.
2. **Encrypted Index Labels**: Hex string HMAC hashes (`L_0`, `L_1`, ...) mapping to AES-256-GCM encrypted document ID payloads.
3. **Audit Events**: Timestamps, operation type (`upload`, `search`, `verify`), touched blob IDs, and matching result counts.

### What the Server CANNOT See:
1. **Zero Plaintext Access**: Plaintext document contents, extracted tokens, search keywords, or query strings are **NEVER** exposed to or stored on the cloud server.
2. **Zero Key Exposure**: Master key (`master.key`) and HKDF derived subkeys (`K_enc`, `K_idx`, `K_tok`) remain exclusively on the client portal.
3. **Cryptographic Tamper Protection**: Any attempt by an insider or cloud provider to modify or swap ciphertext blobs triggers AES-256-GCM authentication failure during verification (`/verify/<doc_id>`).
