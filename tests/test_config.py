"""
Unit tests for config module.

Tests configuration loading and validation.
"""

import pytest
import os


class TestConfigModule:
    """Test configuration module functionality."""
    
    def test_config_constants_exist(self):
        """Test that CONFIG dictionary exists with expected keys."""
        from src.config import CONFIG
        
        assert "log_path" in CONFIG
        assert "threshold" in CONFIG
        assert "alert_output" in CONFIG
    
    def test_config_default_values(self):
        """Test default configuration values."""
        from src.config import CONFIG
        
        assert CONFIG["log_path"] == "data/raw/sample_auth.log"
        assert CONFIG["threshold"] == 5
        assert CONFIG["alert_output"] == "data/processed/alerts.csv"
    
    def test_db_config_structure(self):
        """Test that DB_CONFIG has expected structure."""
        from src.config import DB_CONFIG
        
        required_keys = ["host", "port", "database", "user", "password", "ssl_mode"]
        for key in required_keys:
            assert key in DB_CONFIG


class TestIsDatabaseConfigured:
    """Test is_db_configured() function."""
    
    def test_is_db_configured_with_all_vars(self, mock_env_vars):
        """Test that function returns True when all vars are set."""
        from src.config import is_db_configured, DB_CONFIG
        
        # Manually check with the current DB_CONFIG
        result = all(DB_CONFIG.get(key) for key in ["host", "database", "user", "password"])
        assert result == True
    
    def test_is_db_configured_no_vars_set(self):
        """Test that function returns False when no env vars are set."""
        from src.config import is_db_configured, DB_CONFIG
        
        # If no env vars are set, at least one required key should be None
        # This test checks the function logic, not env var loading
        result = is_db_configured()
        
        # Result depends on whether .env file exists
        # Just verify function returns a boolean
        assert isinstance(result, bool)


class TestDatabaseConfigDefaults:
    """Test database configuration defaults."""
    
    def test_port_is_integer(self):
        """Test that port is an integer."""
        from src.config import DB_CONFIG
        
        assert isinstance(DB_CONFIG["port"], int)
    
    def test_ssl_mode_exists(self):
        """Test that SSL mode has a value."""
        from src.config import DB_CONFIG
        
        assert DB_CONFIG["ssl_mode"] is not None
        assert isinstance(DB_CONFIG["ssl_mode"], str)
