import os
import json
from typing import Dict, Tuple, Optional
from dotenv import load_dotenv, set_key

ENV_FILE = ".env"
CREDENTIALS_FILE = "credentials.json"

def mask_secret(value: str) -> str:
    """Masks secret showing only the last 4 characters."""
    if not value:
        return ""
    val_str = str(value).strip()
    if len(val_str) <= 4:
        return "••••" + val_str
    return "•" * (len(val_str) - 4) + val_str[-4:]

def validate_oauth_json(json_content: str) -> Tuple[bool, Optional[str], Optional[dict]]:
    """
    Validates that OAuth JSON contains expected top-level keys ('installed' or 'web')
    and required inner keys: client_id, client_secret, redirect_uris.
    """
    try:
        data = json.loads(json_content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON syntax: {str(e)}", None

    top_key = None
    if "installed" in data:
        top_key = "installed"
    elif "web" in data:
        top_key = "web"
    elif "client_id" in data and "client_secret" in data:
        # Flattened JSON fallback
        if not data.get("redirect_uris"):
            data["redirect_uris"] = ["http://localhost:5000/oauth2callback"]
        return True, None, {"installed": data}

    if not top_key:
        return False, "OAuth JSON must contain a top-level 'installed' or 'web' object.", None

    inner = data[top_key]
    required_keys = ["client_id", "client_secret"]
    for req in required_keys:
        if req not in inner or not inner[req]:
            return False, f"Missing required OAuth key '{req}' inside '{top_key}'.", None

    if "redirect_uris" not in inner:
        inner["redirect_uris"] = ["http://localhost:5000/oauth2callback"]

    return True, None, data

def save_setup_config(
    gdrive_api_key: str,
    oauth_json_str: Optional[str],
    onedrive_client_id: str,
    onedrive_client_secret: str,
    storage_choice: str
) -> Tuple[bool, str]:
    """
    Saves setup credentials to .env and credentials.json.
    """
    load_dotenv(ENV_FILE)

    # Validate and save OAuth JSON if provided
    if oauth_json_str and oauth_json_str.strip():
        valid, err_msg, parsed_json = validate_oauth_json(oauth_json_str)
        if not valid:
            return False, f"OAuth Credentials Error: {err_msg}"
        with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
            json.dump(parsed_json, f, indent=2)

    # Write to .env
    with open(ENV_FILE, "a") as f:
        pass  # Ensure file exists

    set_key(ENV_FILE, "GDRIVE_API_KEY", gdrive_api_key.strip())
    set_key(ENV_FILE, "ONEDRIVE_CLIENT_ID", onedrive_client_id.strip())
    set_key(ENV_FILE, "ONEDRIVE_CLIENT_SECRET", onedrive_client_secret.strip())
    set_key(ENV_FILE, "STORAGE_CHOICE", storage_choice.strip())
    
    # If storage choice is local, set USE_LOCAL_STORAGE=true, else false
    if storage_choice == "local":
        set_key(ENV_FILE, "USE_LOCAL_STORAGE", "true")
    else:
        set_key(ENV_FILE, "USE_LOCAL_STORAGE", "false")

    # Reload environment variables
    load_dotenv(ENV_FILE, override=True)
    return True, "Settings saved successfully."

def get_masked_config() -> dict:
    """Returns currently saved configuration with masked secrets for display on /setup."""
    load_dotenv(ENV_FILE, override=True)
    gdrive_api_key = os.getenv("GDRIVE_API_KEY", "")
    onedrive_id = os.getenv("ONEDRIVE_CLIENT_ID", "")
    onedrive_secret = os.getenv("ONEDRIVE_CLIENT_SECRET", "")
    storage_choice = os.getenv("STORAGE_CHOICE", "local")
    use_local = os.getenv("USE_LOCAL_STORAGE", "true").lower() == "true"

    has_credentials_json = os.path.exists(CREDENTIALS_FILE)

    return {
        "gdrive_api_key_masked": mask_secret(gdrive_api_key),
        "gdrive_api_key_raw_len": len(gdrive_api_key),
        "onedrive_client_id_masked": mask_secret(onedrive_id),
        "onedrive_client_secret_masked": mask_secret(onedrive_secret),
        "storage_choice": storage_choice,
        "use_local_storage": use_local,
        "has_credentials_json": has_credentials_json,
        "onedrive_configured": bool(onedrive_id and onedrive_secret)
    }
