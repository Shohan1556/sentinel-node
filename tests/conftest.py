"""
Pytest configuration and fixtures for SentinelNode tests.

This module provides reusable fixtures for testing all components.
"""

import pytest
import os
import tempfile
import shutil
from datetime import datetime
from unittest.mock import Mock, MagicMock
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def temp_csv_file(temp_dir):
    """Create a temporary CSV file path."""
    csv_path = os.path.join(temp_dir, "test_alerts.csv")
    yield csv_path
    # Cleanup handled by temp_dir fixture


@pytest.fixture
def sample_log_lines():
    """Provide sample SSH authentication log lines."""
    return [
        # Valid failed login attempts
        "Jan 28 15:30:45 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
        "Jan 28 15:31:00 server sshd[12346]: Failed password for root from 10.0.0.50 port 22 ssh2",
        "Jan 28 15:31:15 server sshd[12347]: Failed password for invalid user test from 172.16.0.25 port 22 ssh2",
        
        # Successful login (should not be parsed as failed)
        "Jan 28 15:32:00 server sshd[12348]: Accepted password for user from 192.168.1.200 port 22 ssh2",
        
        # Malformed entries
        "Jan 28 15:33:00 server sshd[12349]: Some random log entry",
        "Invalid log line without proper format",
        
        # Edge cases
        "Jan 28 15:34:00 server sshd[12350]: Failed password for invalid user admin from 999.999.999.999 port 22 ssh2",  # Invalid IP
    ]


@pytest.fixture
def sample_parsed_events():
    """Provide sample parsed authentication events."""
    base_time = datetime(2026, 1, 28, 15, 30, 0)
    return [
        {
            "timestamp": base_time,
            "ip": "192.168.1.100",
            "event": "failed_login"
        },
        {
            "timestamp": datetime(2026, 1, 28, 15, 31, 0),
            "ip": "10.0.0.50",
            "event": "failed_login"
        },
        {
            "timestamp": datetime(2026, 1, 28, 15, 31, 15),
            "ip": "172.16.0.25",
            "event": "failed_login"
        }
    ]


@pytest.fixture
def sample_log_file(temp_dir):
    """Create a sample auth.log file for testing."""
    log_path = os.path.join(temp_dir, "sample_auth.log")
    
    # Create log content with brute-force pattern
    log_content = """Jan 28 14:00:00 server sshd[1001]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 28 14:00:20 server sshd[1002]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 28 14:00:40 server sshd[1003]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 28 14:01:00 server sshd[1004]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 28 14:01:20 server sshd[1005]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 28 14:02:00 server sshd[1006]: Accepted password for user from 192.168.1.200 port 22 ssh2
Jan 28 14:03:00 server sshd[1007]: Failed password for root from 10.0.0.50 port 22 ssh2
Jan 28 14:03:30 server sshd[1008]: Failed password for root from 10.0.0.50 port 22 ssh2
"""
    
    with open(log_path, 'w') as f:
        f.write(log_content)
    
    yield log_path


@pytest.fixture
def mock_db_connector():
    """Create a mock DatabaseConnector for testing."""
    mock_db = Mock()
    
    # Mock successful operations
    mock_db.test_connection.return_value = True
    mock_db.insert_alert.return_value = 1  # Return alert ID
    mock_db.get_alerts.return_value = [
        {
            'id': 1,
            'timestamp': datetime(2026, 1, 28, 15, 30, 0),
            'ip_address': '192.168.1.100',
            'event_type': 'brute_force',
            'status': 'new',
            'machine_ip': '10.0.0.1',
            'machine_name': 'test-server',
            'browser': 'SSH Client'
        }
    ]
    mock_db.update_alert_status.return_value = True
    mock_db.close.return_value = None
    
    return mock_db


@pytest.fixture
def mock_alert_data():
    """Provide sample alert data for testing."""
    return {
        'timestamp': datetime(2026, 1, 28, 15, 30, 45),
        'ip_address': '192.168.1.100',
        'event_type': 'brute_force',
        'status': 'new',
        'machine_ip': '10.0.0.1',
        'machine_name': 'sentinel-server-01',
        'browser': 'SSH Client'
    }


@pytest.fixture
def sample_brute_force_timestamps():
    """Provide timestamps for brute-force attack simulation."""
    from datetime import timedelta
    
    base = datetime(2026, 1, 28, 14, 0, 0)
    
    # 5 attempts within 90 seconds (should trigger alert)
    rapid_attempts = [base + timedelta(seconds=i * 20) for i in range(5)]
    
    # 4 attempts spread over 3 minutes (should NOT trigger alert)
    slow_attempts = [base + timedelta(minutes=i) for i in range(4)]
    
    return {
        'rapid': rapid_attempts,
        'slow': slow_attempts,
        'base': base
    }


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before each test."""
    # Store original env vars
    original_env = os.environ.copy()
    
    yield
    
    # Restore original env vars
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set mock environment variables for testing."""
    test_env = {
        'DB_HOST': 'test-host.example.com',
        'DB_PORT': '5432',
        'DB_NAME': 'test_db',
        'DB_USER': 'test_user',
        'DB_PASSWORD': 'test_password',
        'DB_SSL_MODE': 'require'
    }
    
    for key, value in test_env.items():
        monkeypatch.setenv(key, value)
    
    return test_env
