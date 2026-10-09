import os
import io
from typing import List, Dict, Optional
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload

SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'


class GoogleDriveClient:
    """
    Google Drive API integration client implementing upload_bytes, download_bytes, and delete_file.
    OAuth login is triggered on demand when requested by the user.
    """

    def __init__(self, credentials_path: str = CREDENTIALS_FILE, token_path: str = TOKEN_FILE):
        self.credentials_path = credentials_path
        self.token_path = token_path
        self.creds: Optional[Credentials] = None
        self.service = None
        self._load_token_if_exists()

    def _load_token_if_exists(self):
        if os.path.exists(self.token_path):
            try:
                self.creds = Credentials.from_authorized_user_file(self.token_path, SCOPES)
                if self.creds and self.creds.expired and self.creds.refresh_token:
                    self.creds.refresh(Request())
                if self.creds and self.creds.valid:
                    self.service = build('drive', 'v3', credentials=self.creds)
                else:
                    self.service = None
            except Exception:
                self.creds = None
                self.service = None
        else:
            self.creds = None
            self.service = None

    def is_authenticated(self) -> bool:
        """Returns True ONLY if valid Google Drive OAuth token.json credentials are loaded and service is built."""
        return self.service is not None and self.creds is not None and self.creds.valid

    def get_auth_url(self, redirect_uri: str = "http://localhost:5000/oauth2callback"):
        """
        Generates OAuth authentication authorization URL for web flow.
        """
        if not os.path.exists(self.credentials_path):
            return None, None
        
        # NOTE: We use Flow, but if Google enforces Installed App restrictions, 
        # using the exact redirect URI is required.
        flow = Flow.from_client_secrets_file(self.credentials_path, SCOPES)
        flow.redirect_uri = redirect_uri
        auth_url, state = flow.authorization_url(prompt='consent', access_type='offline')
        return auth_url, state

    def fetch_token(self, authorization_response: str, redirect_uri: str = "http://localhost:5000/oauth2callback", state: str = None) -> bool:
        """
        Fetches token after user authorization and saves it.
        """
        if not os.path.exists(self.credentials_path):
            raise FileNotFoundError(f"OAuth credentials file '{self.credentials_path}' not found.")
        
        flow = Flow.from_client_secrets_file(self.credentials_path, SCOPES, state=state)
        flow.redirect_uri = redirect_uri
        flow.fetch_token(authorization_response=authorization_response)
        
        self.creds = flow.credentials
        
        # Save authorized user credentials to token.json
        with open(self.token_path, 'w') as token_f:
            token_f.write(self.creds.to_json())

        self.service = build('drive', 'v3', credentials=self.creds)
        return True

    def upload_bytes(self, name: str, data: bytes) -> str:
        """Uploads byte data to Google Drive and returns file ID."""
        if not self.is_authenticated():
            raise RuntimeError("Google Drive client is not authenticated.")

        file_metadata = {'name': name}
        media = MediaIoBaseUpload(io.BytesIO(data), mimetype='application/octet-stream', resumable=True)
        uploaded = self.service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        return uploaded.get('id')

    def download_bytes(self, file_id: str) -> bytes:
        """Downloads byte data from Google Drive for given file ID."""
        if not self.is_authenticated():
            raise RuntimeError("Google Drive client is not authenticated.")

        request = self.service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
        return fh.getvalue()

    def delete_file(self, file_id: str) -> bool:
        """Deletes a file from Google Drive by file ID."""
        if not self.is_authenticated():
            raise RuntimeError("Google Drive client is not authenticated.")
        try:
            self.service.files().delete(fileId=file_id).execute()
            return True
        except Exception:
            return False

    def list_files(self) -> List[Dict]:
        """Lists files uploaded via app in Google Drive."""
        if not self.is_authenticated():
            return []
        try:
            results = self.service.files().list(
                pageSize=100,
                fields="files(id, name, size, modifiedTime)"
            ).execute()
            files = results.get('files', [])
            return [
                {
                    "id": f['id'],
                    "filename": f['name'],
                    "size": int(f.get('size', 0)),
                    "updated_at": f.get('modifiedTime', '')
                }
                for f in files
            ]
        except Exception:
            return []
