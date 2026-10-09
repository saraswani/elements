import os
import secrets
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MASTER_KEY_FILE = "master.key"

def load_or_generate_master_key(filepath: str = MASTER_KEY_FILE) -> bytes:
    """Loads master key from master.key file or generates a new 32-byte key if missing."""
    if os.path.exists(filepath):
        with open(filepath, "rb") as f:
            key = f.read()
            if len(key) == 32:
                return key
    # Generate new 32-byte master key
    key = secrets.token_bytes(32)
    with open(filepath, "wb") as f:
        f.write(key)
    return key

def derive_hkdf_key(master_key: bytes, info_label: bytes, length: int = 32) -> bytes:
    """Derives a cryptographic key using HKDF-SHA256 with the specified info label."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,  # Standard salt-less HKDF for deterministic subkey derivation
        info=info_label,
    )
    return hkdf.derive(master_key)

class CryptoEngine:
    def __init__(self, key_file: str = MASTER_KEY_FILE):
        self.master_key = load_or_generate_master_key(key_file)
        self.k_enc = derive_hkdf_key(self.master_key, b"enc")
        self.k_idx = derive_hkdf_key(self.master_key, b"idx")
        self.k_tok = derive_hkdf_key(self.master_key, b"tok")
        self.k_blind = derive_hkdf_key(self.master_key, b"blind")

    def encrypt_document(self, doc_id: str, plaintext: bytes) -> bytes:
        """
        Encrypts document bytes with AES-256-GCM.
        AAD is set to doc_id so ciphertext blobs cannot be swapped between documents.
        Returns: nonce (12 bytes) + ciphertext_with_tag
        """
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.k_enc)
        aad = doc_id.encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt_document(self, doc_id: str, blob: bytes) -> bytes:
        """
        Decrypts AES-256-GCM document blob.
        Verifies non-tampering and AAD matching doc_id.
        Raises InvalidTag if tampered or mismatched doc_id.
        """
        if len(blob) < 12 + 16:  # 12-byte nonce + 16-byte minimum tag/data
            raise ValueError("Invalid document blob size.")
        nonce = blob[:12]
        ciphertext = blob[12:]
        aesgcm = AESGCM(self.k_enc)
        aad = doc_id.encode("utf-8")
        return aesgcm.decrypt(nonce, ciphertext, aad)

    def verify_document_blob(self, doc_id: str, blob: bytes) -> dict:
        """
        Verifies the AES-GCM tag and document ID association.
        Returns detailed verification outcome.
        """
        try:
            self.decrypt_document(doc_id, blob)
            return {
                "valid": True,
                "doc_id": doc_id,
                "blob_size": len(blob),
                "nonce_hex": blob[:12].hex(),
                "tag_verified": True,
                "aad_verified": True,
                "message": "AES-256-GCM Tag and AAD binding verified successfully."
            }
        except InvalidTag:
            return {
                "valid": False,
                "doc_id": doc_id,
                "blob_size": len(blob),
                "tag_verified": False,
                "aad_verified": False,
                "message": "Verification failed: Blob tampered or mismatched Document ID (GCM tag invalid)."
            }
        except Exception as e:
            return {
                "valid": False,
                "doc_id": doc_id,
                "blob_size": len(blob) if blob else 0,
                "tag_verified": False,
                "aad_verified": False,
                "message": f"Verification error: {str(e)}"
            }
