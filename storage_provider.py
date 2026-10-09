import os
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from drive_client import GoogleDriveClient

LOCAL_STORE_DIR = "./local_store"

class StorageProvider(ABC):
    """Abstract storage provider interface."""

    @abstractmethod
    def upload_bytes(self, filename: str, data: bytes) -> str:
        """Uploads ciphertext blob bytes and returns unique file_id."""
        pass

    @abstractmethod
    def download_bytes(self, file_id: str) -> bytes:
        """Downloads ciphertext blob bytes for given file_id."""
        pass

    @abstractmethod
    def delete_file(self, file_id: str) -> bool:
        """Deletes file blob by file_id."""
        pass

    @abstractmethod
    def list_files(self) -> List[Dict]:
        """Lists metadata of stored blobs."""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Returns human-readable provider name."""
        pass


class LocalStorageProvider(StorageProvider):
    """Local filesystem storage provider storing blobs in ./local_store/."""

    def __init__(self, store_dir: str = LOCAL_STORE_DIR):
        self.store_dir = store_dir
        os.makedirs(self.store_dir, exist_ok=True)

    def upload_bytes(self, filename: str, data: bytes) -> str:
        # File ID is filename
        file_path = os.path.join(self.store_dir, filename)
        with open(file_path, "wb") as f:
            f.write(data)
        return filename

    def download_bytes(self, file_id: str) -> bytes:
        file_path = os.path.join(self.store_dir, file_id)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File blob '{file_id}' not found in local store.")
        with open(file_path, "rb") as f:
            return f.read()

    def delete_file(self, file_id: str) -> bool:
        file_path = os.path.join(self.store_dir, file_id)
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False

    def list_files(self) -> List[Dict]:
        files = []
        if os.path.exists(self.store_dir):
            for name in os.listdir(self.store_dir):
                path = os.path.join(self.store_dir, name)
                if os.path.isfile(path):
                    stat = os.stat(path)
                    files.append({
                        "id": name,
                        "filename": name,
                        "size": stat.st_size,
                        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime))
                    })
        return files

    def get_provider_name(self) -> str:
        return "Local Storage (./local_store)"


class GoogleDriveStorageProvider(StorageProvider):
    """Google Drive storage provider using Drive API v3."""

    def __init__(self, drive_client: Optional[GoogleDriveClient] = None):
        self.client = drive_client or GoogleDriveClient()

    def upload_bytes(self, filename: str, data: bytes) -> str:
        return self.client.upload_bytes(filename, data)

    def download_bytes(self, file_id: str) -> bytes:
        return self.client.download_bytes(file_id)

    def delete_file(self, file_id: str) -> bool:
        return self.client.delete_file(file_id)

    def list_files(self) -> List[Dict]:
        return self.client.list_files()

    def get_provider_name(self) -> str:
        return "Google Drive"


class OneDriveStorageProvider(StorageProvider):
    """
    [OPTIONAL STUB]
    OneDrive storage provider interface ready for Microsoft Graph API integration.
    """

    def __init__(self, client_id: str = "", client_secret: str = ""):
        self.client_id = client_id
        self.client_secret = client_secret

    def upload_bytes(self, filename: str, data: bytes) -> str:
        raise NotImplementedError("OneDrive provider is not fully configured yet.")

    def download_bytes(self, file_id: str) -> bytes:
        raise NotImplementedError("OneDrive provider is not fully configured yet.")

    def delete_file(self, file_id: str) -> bool:
        raise NotImplementedError("OneDrive provider is not fully configured yet.")

    def list_files(self) -> List[Dict]:
        return []

    def get_provider_name(self) -> str:
        return "OneDrive (Not Configured)"


def get_storage_provider(provider_type: Optional[str] = None) -> StorageProvider:
    """
    Factory function returning active storage provider based on environment setting
    or request param. Default is LocalStorageProvider when USE_LOCAL_STORAGE=true.
    """
    use_local = os.getenv("USE_LOCAL_STORAGE", "true").lower() == "true"
    chosen_provider = provider_type or os.getenv("STORAGE_CHOICE", "gdrive" if not use_local else "local")

    if use_local or chosen_provider == "local":
        return LocalStorageProvider()
    elif chosen_provider == "gdrive":
        client = GoogleDriveClient()
        if client.is_authenticated():
            return GoogleDriveStorageProvider(client)
        else:
            # Fallback to local storage if Google Drive is selected but not authenticated
            return LocalStorageProvider()
    elif chosen_provider == "onedrive":
        return OneDriveStorageProvider()
    else:
        return LocalStorageProvider()
