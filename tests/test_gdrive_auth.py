import io
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from app import app

class TestGoogleDriveAuthEnforcement(unittest.TestCase):
    def setUp(self):
        self.app_client = app.test_client()
        self.app_client.testing = True

    @patch("drive_client.GoogleDriveClient.is_authenticated")
    @patch.dict(os.environ, {"USE_LOCAL_STORAGE": "false"})
    def test_upload_refuses_without_token(self, mock_is_auth):
        # Mock is_authenticated to return False (simulating absence of valid token.json)
        mock_is_auth.return_value = False

        data = {
            "file": (io.BytesIO(b"Secret tax document content"), "tax_report.txt")
        }

        response = self.app_client.post(
            "/upload",
            data=data,
            content_type="multipart/form-data",
            headers={"Accept": "application/json"}
        )

        self.assertEqual(response.status_code, 401)
        json_resp = response.get_json()
        self.assertEqual(json_resp["status"], "error")
        self.assertIn("Google Drive is not connected. Click Connect Google Drive first.", json_resp["message"])


if __name__ == "__main__":
    unittest.main()
