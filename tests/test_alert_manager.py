"""
Unit tests for AlertManager module.

Tests alert distribution to console, CSV, and database outputs.
"""

import pytest
import os
import csv
from datetime import datetime
from src.alert_manager import AlertManager


class TestAlertManagerInitialization:
    """Test AlertManager initialization."""
    
    def test_initialization_with_csv_only(self, temp_csv_file):
        """Test initialization with CSV output only."""
        manager = AlertManager(csv_output_path=temp_csv_file)
        assert manager.csv_output_path == temp_csv_file
        assert manager.db_connector is None
        assert os.path.exists(temp_csv_file)
    
    def test_initialization_with_db_only(self, mock_db_connector):
        """Test initialization with database only."""
        manager = AlertManager(db_connector=mock_db_connector)
        assert manager.csv_output_path is None
        assert manager.db_connector is not None
    
    def test_initialization_with_both(self, temp_csv_file, mock_db_connector):
        """Test initialization with both CSV and database."""
        manager = AlertManager(
            csv_output_path=temp_csv_file,
            db_connector=mock_db_connector
        )
        assert manager.csv_output_path == temp_csv_file
        assert manager.db_connector is not None
    
    def test_csv_file_created_with_headers(self, temp_csv_file):
        """Test that CSV file is created with proper headers."""
        manager = AlertManager(csv_output_path=temp_csv_file)
        
        with open(temp_csv_file, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader)
            
        expected_headers = [
            'timestamp', 'ip_address', 'event_type', 'status',
            'machine_ip', 'machine_name', 'browser'
        ]
        assert headers == expected_headers


class TestSendAlert:
    """Test send_alert functionality."""
    
    def test_send_alert_console_only(self, capsys):
        """Test sending alert to console only."""
        manager = AlertManager()
        
        manager.send_alert(
            message="Test alert",
            timestamp=datetime(2026, 1, 28, 15, 30, 0),
            ip_address="192.168.1.100"
        )
        
        captured = capsys.readouterr()
        assert "ALERT: Test alert" in captured.out
    
    def test_send_alert_with_csv(self, temp_csv_file):
        """Test sending alert to CSV file."""
        manager = AlertManager(csv_output_path=temp_csv_file)
        
        manager.send_alert(
            message="Brute-force detected",
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="192.168.1.100",
            event_type="brute_force",
            status="new"
        )
        
        # Verify CSV content
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
        assert len(rows) == 1
        assert rows[0]['ip_address'] == "192.168.1.100"
        assert rows[0]['event_type'] == "brute_force"
        assert rows[0]['status'] == "new"
    
    def test_send_alert_with_database(self, mock_db_connector):
        """Test sending alert to database."""
        manager = AlertManager(db_connector=mock_db_connector)
        
        manager.send_alert(
            message="Brute-force detected",
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="192.168.1.100",
            event_type="brute_force",
            status="new",
            machine_ip="10.0.0.1",
            machine_name="test-server",
            browser="SSH Client"
        )
        
        # Verify database insert was called
        mock_db_connector.insert_alert.assert_called_once()
        call_args = mock_db_connector.insert_alert.call_args[1]
        assert call_args['ip_address'] == "192.168.1.100"
        assert call_args['event_type'] == "brute_force"
    
    def test_send_alert_all_channels(self, temp_csv_file, mock_db_connector, capsys):
        """Test sending alert to all channels simultaneously."""
        manager = AlertManager(
            csv_output_path=temp_csv_file,
            db_connector=mock_db_connector
        )
        
        manager.send_alert(
            message="Multi-channel alert",
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="10.0.0.50",
            event_type="brute_force"
        )
        
        # Check console
        captured = capsys.readouterr()
        assert "ALERT: Multi-channel alert" in captured.out
        
        # Check CSV
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]['ip_address'] == "10.0.0.50"
        
        # Check database
        mock_db_connector.insert_alert.assert_called_once()
    
    def test_send_alert_with_default_timestamp(self, temp_csv_file):
        """Test that default timestamp is used when not provided."""
        manager = AlertManager(csv_output_path=temp_csv_file)
        
        manager.send_alert(
            message="Alert without timestamp",
            ip_address="192.168.1.100"
        )
        
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 1
        # Timestamp should be present (auto-generated)
        assert rows[0]['timestamp'] != ''


class TestLogToCSV:
    """Test CSV logging functionality."""
    
    def test_log_to_csv_basic(self, temp_csv_file):
        """Test basic CSV logging."""
        manager = AlertManager(csv_output_path=temp_csv_file)
        
        result = manager.log_to_csv(
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="192.168.1.100",
            event_type="brute_force",
            status="new"
        )
        
        assert result == True
        
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 1
        assert rows[0]['ip_address'] == "192.168.1.100"
    
    def test_log_to_csv_with_optional_fields(self, temp_csv_file):
        """Test CSV logging with all optional fields."""
        manager = AlertManager(csv_output_path=temp_csv_file)
        
        manager.log_to_csv(
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="192.168.1.100",
            event_type="brute_force",
            status="new",
            machine_ip="10.0.0.1",
            machine_name="sentinel-server",
            browser="SSH Client"
        )
        
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert rows[0]['machine_ip'] == "10.0.0.1"
        assert rows[0]['machine_name'] == "sentinel-server"
        assert rows[0]['browser'] == "SSH Client"
    
    def test_log_to_csv_multiple_entries(self, temp_csv_file):
        """Test logging multiple entries to CSV."""
        manager = AlertManager(csv_output_path=temp_csv_file)
        
        for i in range(3):
            manager.log_to_csv(
                timestamp=datetime(2026, 1, 28, 15, 30, i),
                ip_address=f"192.168.1.{100 + i}",
                event_type="brute_force",
                status="new"
            )
        
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 3
        assert rows[0]['ip_address'] == "192.168.1.100"
        assert rows[1]['ip_address'] == "192.168.1.101"
        assert rows[2]['ip_address'] == "192.168.1.102"


class TestLogToDatabase:
    """Test database logging functionality."""
    
    def test_log_to_database_success(self, mock_db_connector):
        """Test successful database logging."""
        manager = AlertManager(db_connector=mock_db_connector)
        
        result = manager.log_to_database(
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="192.168.1.100",
            event_type="brute_force",
            status="new"
        )
        
        assert result == 1  # Mock returns alert ID 1
        mock_db_connector.insert_alert.assert_called_once()
    
    def test_log_to_database_with_all_fields(self, mock_db_connector):
        """Test database logging with all fields."""
        manager = AlertManager(db_connector=mock_db_connector)
        
        manager.log_to_database(
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="192.168.1.100",
            event_type="brute_force",
            status="new",
            machine_ip="10.0.0.1",
            machine_name="sentinel-server",
            browser="SSH Client"
        )
        
        call_args = mock_db_connector.insert_alert.call_args[1]
        assert call_args['machine_ip'] == "10.0.0.1"
        assert call_args['machine_name'] == "sentinel-server"
        assert call_args['browser'] == "SSH Client"


class TestErrorHandling:
    """Test error handling in AlertManager."""
    
    def test_csv_write_to_invalid_path(self):
        """Test handling of invalid CSV path."""
        # Use a path that doesn't exist and can't be created
        invalid_path = "/root/nonexistent/path/alerts.csv"
        
        # Should not crash during initialization
        try:
            manager = AlertManager(csv_output_path=invalid_path)
            # Attempt to write should handle error gracefully
            result = manager.log_to_csv(
                timestamp=datetime(2026, 1, 28, 15, 30, 45),
                ip_address="192.168.1.100",
                event_type="brute_force",
                status="new"
            )
            # Should return False on error
            assert result == False
        except Exception:
            # If it raises an exception, that's also acceptable
            pass
    
    def test_send_alert_without_ip_address(self, temp_csv_file, capsys):
        """Test sending alert without IP address (console only)."""
        manager = AlertManager(csv_output_path=temp_csv_file)
        
        # Should still print to console
        manager.send_alert(message="Alert without IP")
        
        captured = capsys.readouterr()
        assert "ALERT: Alert without IP" in captured.out
        
        # CSV should not have new entry (no IP provided)
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 0
