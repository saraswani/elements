import os
import time
import uuid
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from dotenv import load_dotenv

from crypto_engine import CryptoEngine
from sse_index import SSEIndex
from boolean_parser import evaluate_boolean_query
from storage_provider import get_storage_provider, StorageProvider
from audit_logger import log_audit_event, read_audit_log
from config_manager import get_masked_config, save_setup_config

load_dotenv(".env", override=True)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "sse_engine_hackathon_demo_secret_2026")

# Allow local HTTP for OAuth2 callback
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize Cryptographic Engine and SSE Index
crypto_engine = CryptoEngine()
sse_index = SSEIndex(
    k_idx=crypto_engine.k_idx,
    k_tok=crypto_engine.k_tok,
    k_blind=crypto_engine.k_blind
)

def get_current_storage() -> StorageProvider:
    return get_storage_provider()

import io
try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

def extract_file_text(file_bytes: bytes, filename: str) -> str:
    """Extracts searchable text from PDF or standard text/document files."""
    if filename.lower().endswith(".pdf") and PYPDF_AVAILABLE:
        try:
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            extracted_pages = [page.extract_text() for page in reader.pages if page.extract_text()]
            full_text = "\n".join(extracted_pages).strip()
            if full_text:
                return full_text
        except Exception:
            pass
    return file_bytes.decode("utf-8", errors="replace")


@app.context_processor
def inject_global_variables():
    from drive_client import GoogleDriveClient
    storage = get_current_storage()
    # Force use of Google Drive instead of local
    use_local = False
    gdrive_client = GoogleDriveClient()
    is_gdrive_connected = gdrive_client.is_authenticated()
    return {
        "active_provider_name": "Google Drive",
        "use_local_storage": False,
        "is_gdrive_connected": is_gdrive_connected
    }


@app.route("/preview-encrypt", methods=["POST"])
def preview_encrypt():
    file_obj = request.files.get("file")
    if not file_obj or not file_obj.filename:
        return jsonify({"status": "error", "message": "No file selected"}), 400

    raw_bytes = file_obj.read()
    filename = file_obj.filename

    uid = uuid.uuid4().hex[:8]
    clean_name = "".join([c for c in filename if c.isalnum() or c in ("-", "_", ".")]).strip()
    doc_id = f"{clean_name}_{uid}" if clean_name else f"doc_{uid}"

    ciphertext_blob = crypto_engine.encrypt_document(doc_id, raw_bytes)

    nonce_hex = ciphertext_blob[:12].hex()
    ciphertext_hex = ciphertext_blob[12:].hex()
    ciphertext_64 = ciphertext_hex[:64] if len(ciphertext_hex) >= 64 else ciphertext_hex.ljust(64, '0')

    return jsonify({
        "status": "success",
        "doc_id": doc_id,
        "blob_size": len(ciphertext_blob),
        "nonce_hex": nonce_hex,
        "ciphertext_preview_64": ciphertext_64
    })


@app.route("/", methods=["GET"])
def index():
    from drive_client import GoogleDriveClient
    gdrive_client = GoogleDriveClient()
    if not gdrive_client.is_authenticated():
        return redirect(url_for("login"))

    query_str = request.args.get("q", "").strip()
    storage = get_current_storage()
    
    results = []
    queried_labels = []
    execution_time_ms = 0

    if query_str:
        start_time = time.time()
        
        # Callback to fetch keyword trapdoor doc IDs
        def fetch_keyword_docs(keyword: str):
            matching_ids, labels = sse_index.search_keyword(keyword)
            return matching_ids, labels

        # Get all known doc IDs for unary NOT operations
        all_files = storage.list_files()
        all_known_doc_ids = {f["filename"] for f in all_files}

        matching_doc_ids, queried_labels = evaluate_boolean_query(
            query_str, fetch_keyword_docs, all_known_doc_ids
        )

        # Download & Decrypt matching documents
        for doc_id in matching_doc_ids:
            try:
                blob = storage.download_bytes(doc_id)
                decrypted_bytes = crypto_engine.decrypt_document(doc_id, blob)
                decrypted_text = extract_file_text(decrypted_bytes, doc_id)
                results.append({
                    "doc_id": doc_id,
                    "decrypted_text": decrypted_text,
                    "verified": True
                })
            except Exception as e:
                results.append({
                    "doc_id": doc_id,
                    "decrypted_text": f"[Decryption Error: {str(e)}]",
                    "verified": False
                })

        execution_time_ms = round((time.time() - start_time) * 1000, 2)

        # Audit Logging
        log_audit_event(
            operation="search",
            blob_ids=list(matching_doc_ids),
            label_hashes=queried_labels,
            result_count=len(matching_doc_ids)
        )

    stored_files = storage.list_files()

    return render_template(
        "index.html",
        query_str=query_str,
        results=results,
        queried_labels=queried_labels,
        execution_time_ms=execution_time_ms,
        stored_files=stored_files
    )


@app.route("/upload", methods=["POST"])
def upload_document():
    file_obj = request.files.get("file")

    if not file_obj or not file_obj.filename:
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"status": "error", "message": "No file selected."}), 400
        flash("Please select a file to upload.", "danger")
        return redirect(url_for("index"))

    # Enforce Google Drive and ensure auth
    use_local = False
    storage = get_current_storage()

    from drive_client import GoogleDriveClient
    drive_client = GoogleDriveClient()
    if not drive_client.is_authenticated():
        err_msg = "Google Drive is not connected. Please login first."
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"status": "error", "message": err_msg}), 401
        flash(err_msg, "danger")
        return redirect(url_for("login"))

    raw_bytes = file_obj.read()
    filename = file_obj.filename

    # Extract searchable text content (supports PDF, TXT, CSV, MD, etc.)
    text_content = extract_file_text(raw_bytes, filename)

    # Generate document ID
    uid = uuid.uuid4().hex[:8]
    clean_name = "".join([c for c in filename if c.isalnum() or c in ("-", "_", ".")]).strip()
    doc_id = f"{clean_name}_{uid}" if clean_name else f"doc_{uid}"

    # 1. Encrypt raw document bytes using AES-256-GCM (doc_id as AAD)
    ciphertext_blob = crypto_engine.encrypt_document(doc_id, raw_bytes)

    # 2. Upload ciphertext blob to storage provider (catching errors gracefully)
    try:
        stored_file_id = storage.upload_bytes(doc_id, ciphertext_blob)
    except Exception as e:
        err_msg = f"Upload Error: {str(e)}"
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"status": "error", "message": err_msg}), 500
        flash(err_msg, "danger")
        return redirect(url_for("index"))

    # 3. Update SSE Search Index (Label hashes only)
    generated_labels = sse_index.add_document(doc_id, text_content)

    # 4. Log Audit Event
    log_audit_event(
        operation="upload",
        blob_ids=[doc_id],
        label_hashes=generated_labels,
        result_count=1
    )

    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({
            "status": "success",
            "doc_id": doc_id,
            "stored_file_id": stored_file_id,
            "blob_size": len(ciphertext_blob),
            "generated_labels_count": len(generated_labels)
        })

    provider_label = "Google Drive" if not use_local else "Local Storage"
    flash(f"Document encrypted & uploaded to {provider_label}! File ID: {stored_file_id}", "success")
    return redirect(url_for("index"))


@app.route("/search", methods=["GET"])
def search_api():
    query_str = request.args.get("q", "").strip()
    if not query_str:
        return jsonify({"query": "", "results_count": 0, "results": [], "telemetry": {}})

    start_time = time.time()
    storage = get_current_storage()

    def fetch_keyword_docs(keyword: str):
        return sse_index.search_keyword(keyword)

    all_files = storage.list_files()
    all_known_doc_ids = {f["filename"] for f in all_files}

    matching_doc_ids, queried_labels = evaluate_boolean_query(
        query_str, fetch_keyword_docs, all_known_doc_ids
    )

    results = []
    for doc_id in matching_doc_ids:
        try:
            blob = storage.download_bytes(doc_id)
            decrypted_bytes = crypto_engine.decrypt_document(doc_id, blob)
            decrypted_text = decrypted_bytes.decode("utf-8", errors="replace")
            results.append({
                "doc_id": doc_id,
                "decrypted_text": decrypted_text,
                "verified": True
            })
        except Exception as e:
            results.append({
                "doc_id": doc_id,
                "decrypted_text": None,
                "error": str(e),
                "verified": False
            })

    execution_time_ms = round((time.time() - start_time) * 1000, 2)

    log_audit_event(
        operation="search",
        blob_ids=list(matching_doc_ids),
        label_hashes=queried_labels,
        result_count=len(matching_doc_ids)
    )

    return jsonify({
        "query": query_str,
        "results_count": len(results),
        "matching_doc_ids": list(matching_doc_ids),
        "results": results,
        "telemetry": {
            "queried_labels_count": len(queried_labels),
            "execution_time_ms": execution_time_ms
        }
    })


@app.route("/verify/<doc_id>", methods=["GET"])
def verify_document(doc_id: str):
    storage = get_current_storage()
    try:
        blob = storage.download_bytes(doc_id)
    except Exception as e:
        res = {
            "status": "error",
            "doc_id": doc_id,
            "verified": False,
            "message": f"Storage download error: {str(e)}"
        }
        log_audit_event("verify", blob_ids=[doc_id], label_hashes=[], result_count=0)
        return jsonify(res), 404

    # 1. Cryptographic GCM Tag & AAD Verification
    crypto_verification = crypto_engine.verify_document_blob(doc_id, blob)

    # 2. Index Integrity Verification (if blob is decryptable)
    index_verification = {"verified": False, "message": "N/A"}
    if crypto_verification["valid"]:
        try:
            plaintext = crypto_engine.decrypt_document(doc_id, blob).decode("utf-8", errors="replace")
            index_verification = sse_index.verify_index_entry(doc_id, plaintext)
        except Exception as e:
            index_verification = {"verified": False, "error": str(e)}

    overall_verified = crypto_verification["valid"] and index_verification.get("verified", False)

    log_audit_event("verify", blob_ids=[doc_id], label_hashes=[], result_count=1 if overall_verified else 0)

    result_json = {
        "status": "success",
        "doc_id": doc_id,
        "overall_verified": overall_verified,
        "crypto_proof": crypto_verification,
        "index_integrity": index_verification
    }

    if request.headers.get("Accept") == "application/json" or request.args.get("format") == "json":
        return jsonify(result_json)

    if overall_verified:
        flash(f"Cryptographic Verification PASSED for document '{doc_id}'. GCM Tag & Index Integrity intact.", "success")
    else:
        flash(f"Cryptographic Verification FAILED for document '{doc_id}'. Tampering or invalid tag detected.", "danger")

    return redirect(url_for("index"))


@app.route("/server-view", methods=["GET"])
def server_view():
    storage = get_current_storage()
    stored_files = storage.list_files()

    blob_items = []
    for f in stored_files:
        try:
            raw_blob = storage.download_bytes(f["filename"])
            preview_hex = raw_blob[:16].hex()
        except Exception:
            preview_hex = "ERROR"

        blob_items.append({
            "blob_id": f["filename"],
            "size": f["size"],
            "hex_preview": preview_hex
        })

    index_labels = sse_index.data.get("labels", {})
    audit_records = read_audit_log()

    return render_template(
        "server_view.html",
        blob_items=blob_items,
        index_labels=index_labels,
        audit_records=audit_records
    )


@app.route("/login", methods=["GET"])
def login():
    from drive_client import GoogleDriveClient
    gdrive_client = GoogleDriveClient()
    if gdrive_client.is_authenticated():
        return redirect(url_for("index"))
    
    # Render a landing page with a Google Login button
    return render_template("login.html")


@app.route("/auth/google", methods=["GET"])
def auth_google():
    from drive_client import GoogleDriveClient
    client = GoogleDriveClient()
    from google_auth_oauthlib.flow import Flow
    import os
    if not os.path.exists(client.credentials_path):
        flash("Google OAuth is not configured properly.", "danger")
        return redirect(url_for("login"))
        
    flow = Flow.from_client_secrets_file(client.credentials_path, ['https://www.googleapis.com/auth/drive.file'])
    flow.redirect_uri = url_for("oauth2callback", _external=True)
    auth_url, state = flow.authorization_url(prompt='consent', access_type='offline')
    
    from flask import session
    session['oauth_state'] = state
    # Save the PKCE code verifier if it exists
    if hasattr(flow, 'code_verifier'):
        session['code_verifier'] = flow.code_verifier
        
    return redirect(auth_url)


@app.route("/oauth2callback", methods=["GET"])
def oauth2callback():
    from drive_client import GoogleDriveClient
    from flask import session
    from google_auth_oauthlib.flow import Flow
    import os
    
    client = GoogleDriveClient()
    state = session.get('oauth_state')
    code_verifier = session.get('code_verifier')
    
    authorization_response = request.url
    try:
        if "error" in request.args:
            flash(f"OAuth Error: {request.args.get('error')}", "danger")
            return redirect(url_for("login"))
            
        flow = Flow.from_client_secrets_file(client.credentials_path, ['https://www.googleapis.com/auth/drive.file'], state=state)
        flow.redirect_uri = url_for("oauth2callback", _external=True)
        
        # Restore PKCE code verifier
        if code_verifier:
            flow.code_verifier = code_verifier
            
        flow.fetch_token(authorization_response=authorization_response)
        
        client.creds = flow.credentials
        with open(client.token_path, 'w') as token_f:
            token_f.write(client.creds.to_json())
            
        from googleapiclient.discovery import build
        client.service = build('drive', 'v3', credentials=client.creds)
        
        flash("Logged in with Google successfully!", "success")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Failed to connect Google Drive: {str(e)}", "danger")
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    import os
    if os.path.exists("token.json"):
        os.remove("token.json")
    from flask import session
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
