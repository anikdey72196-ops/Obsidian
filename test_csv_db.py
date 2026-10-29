import pytest
from unittest.mock import patch
import csv_db

def test_get_user_by_email_missing_file():
    with patch('os.path.exists') as mock_exists:
        mock_exists.return_value = False
        result = csv_db.get_user_by_email('test@example.com')
        assert result is None
        mock_exists.assert_called_once_with(csv_db.USERS_FILE)
