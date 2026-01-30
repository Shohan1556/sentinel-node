"""
Unit tests for DatabaseConnector module.

Tests database connection, CRUD operations, and error handling.
Note: These tests use mocking to avoid requiring actual database connection.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from src.db_connector import DatabaseConnector


class TestDatabaseConnectorInitialization:
    """Test DatabaseConnector initialization."""
    
    @patch('src.db_connector.psycopg2.pool.SimpleConnectionPool')
    def test_initialization_with_defaults(self, mock_pool):
        """Test initialization with default parameters."""
        # Mock the pool and connection
        mock_conn = MagicMock()
        mock_pool_instance = MagicMock()
        mock_pool_instance.getconn.return_value = mock_conn
        mock_pool.return_value = mock_pool_instance
        
        db = DatabaseConnector(
            host="test-host.example.com",
            port=5432,
            database="test_db",
            user="test_user",
            password="test_password"
        )
        
        assert db.host == "test-host.example.com"
        assert db.port == 5432
        assert db.database == "test_db"
        assert db.user == "test_user"


class TestAlertInsertion:
    """Test alert insertion functionality."""
    
    @patch('src.db_connector.psycopg2.pool.SimpleConnectionPool')
    def test_insert_alert_basic(self, mock_pool):
        """Test basic alert insertion."""
        # Setup mocks
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = [1]  # Return alert ID as list
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        
        mock_pool_instance = MagicMock()
        mock_pool_instance.getconn.return_value = mock_conn
        mock_pool.return_value = mock_pool_instance
        
        db = DatabaseConnector(
            host="test-host.example.com",
            port=5432,
            database="test_db",
            user="test_user",
            password="test_password"
        )
        
        # Insert alert
        alert_id = db.insert_alert(
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="192.168.1.100",
            event_type="brute_force",
            status="new"
        )
        
        assert alert_id == 1
        assert mock_cursor.execute.called
        assert mock_conn.commit.called


class TestAlertRetrieval:
    """Test alert retrieval functionality."""
    
    @patch('src.db_connector.psycopg2.pool.SimpleConnectionPool')
    def test_get_alerts_default(self, mock_pool):
        """Test getting alerts with default parameters."""
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {
                'id': 1,
                'timestamp': datetime(2026, 1, 28, 15, 30, 0),
                'ip_address': '192.168.1.100',
                'event_type': 'brute_force',
                'status': 'new'
            }
        ]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        
        mock_pool_instance = MagicMock()
        mock_pool_instance.getconn.return_value = mock_conn
        mock_pool.return_value = mock_pool_instance
        
        db = DatabaseConnector(
            host="test-host.example.com",
            port=5432,
            database="test_db",
            user="test_user",
            password="test_password"
        )
        
        alerts = db.get_alerts()
        
        assert len(alerts) == 1
        assert alerts[0]['ip_address'] == '192.168.1.100'


class TestAlertStatusUpdate:
    """Test alert status update functionality."""
    
    @patch('src.db_connector.psycopg2.pool.SimpleConnectionPool')
    def test_update_alert_status_success(self, mock_pool):
        """Test successful alert status update."""
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        
        mock_pool_instance = MagicMock()
        mock_pool_instance.getconn.return_value = mock_conn
        mock_pool.return_value = mock_pool_instance
        
        db = DatabaseConnector(
            host="test-host.example.com",
            port=5432,
            database="test_db",
            user="test_user",
            password="test_password"
        )
        
        result = db.update_alert_status(1, "acknowledged")
        
        assert result == True
        assert mock_cursor.execute.called
        assert mock_conn.commit.called


class TestConnectionManagement:
    """Test connection pool management."""
    
    @patch('src.db_connector.psycopg2.pool.SimpleConnectionPool')
    def test_close_pool(self, mock_pool):
        """Test closing connection pool."""
        mock_pool_instance = MagicMock()
        mock_pool.return_value = mock_pool_instance
        
        # Mock connection for _initialize_schema
        mock_conn = MagicMock()
        mock_pool_instance.getconn.return_value = mock_conn
        
        db = DatabaseConnector(
            host="test-host.example.com",
            port=5432,
            database="test_db",
            user="test_user",
            password="test_password"
        )
        
        db.close()
        
        mock_pool_instance.closeall.assert_called_once()


class TestErrorHandling:
    """Test error handling in database operations."""
    
    @patch('src.db_connector.psycopg2.pool.SimpleConnectionPool')
    def test_insert_alert_database_error(self, mock_pool):
        """Test handling of database errors during insert."""
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = [None, Exception("Database error")]  # First call succeeds (schema), second fails
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        
        mock_pool_instance = MagicMock()
        mock_pool_instance.getconn.return_value = mock_conn
        mock_pool.return_value = mock_pool_instance
        
        db = DatabaseConnector(
            host="test-host.example.com",
            port=5432,
            database="test_db",
            user="test_user",
            password="test_password"
        )
        
        alert_id = db.insert_alert(
            timestamp=datetime(2026, 1, 28, 15, 30, 45),
            ip_address="192.168.1.100",
            event_type="brute_force",
            status="new"
        )
        
        # Should return None on error
        assert alert_id is None
        # Should rollback on error
        assert mock_conn.rollback.called
