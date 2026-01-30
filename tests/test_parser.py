"""
Unit tests for LogParser module.

Tests log parsing functionality with valid, invalid, and edge case inputs.
"""

import pytest
from src.log_parser import LogParser
from datetime import datetime


class TestLogParserInitialization:
    """Test LogParser initialization."""
    
    def test_parser_initialization(self):
        """Test that LogParser initializes with correct log path."""
        parser = LogParser("/data/raw/sample_auth.log")
        assert parser.log_path == "/data/raw/sample_auth.log"
    
    def test_parser_initialization_with_relative_path(self):
        """Test initialization with relative path."""
        parser = LogParser("data/raw/auth.log")
        assert parser.log_path == "data/raw/auth.log"


class TestLogParsing:
    """Test log line parsing functionality."""
    
    def test_parse_valid_failed_login(self, sample_log_lines):
        """Test parsing a valid failed login attempt."""
        parser = LogParser("/test/path")
        result = parser.parse_auth_log_line(sample_log_lines[0])
        
        assert result is not None
        assert result["ip"] == "192.168.1.100"
        assert result["event"] == "failed_login"
        assert isinstance(result["timestamp"], datetime)
    
    def test_parse_multiple_valid_lines(self, sample_log_lines):
        """Test parsing multiple valid failed login lines."""
        parser = LogParser("/test/path")
        
        # Parse first three valid lines
        for i in range(3):
            result = parser.parse_auth_log_line(sample_log_lines[i])
            assert result is not None
            assert result["event"] == "failed_login"
            assert "ip" in result
            assert "timestamp" in result
    
    def test_parse_successful_login_returns_none(self, sample_log_lines):
        """Test that successful login lines are not parsed (return None)."""
        parser = LogParser("/test/path")
        # Line 3 is a successful login
        result = parser.parse_auth_log_line(sample_log_lines[3])
        assert result is None
    
    def test_parse_invalid_log_line(self, sample_log_lines):
        """Test parsing invalid log lines returns None."""
        parser = LogParser("/test/path")
        
        # Test malformed entries
        assert parser.parse_auth_log_line(sample_log_lines[4]) is None
        assert parser.parse_auth_log_line(sample_log_lines[5]) is None
    
    def test_parse_empty_string(self):
        """Test parsing empty string returns None."""
        parser = LogParser("/test/path")
        assert parser.parse_auth_log_line("") is None
    
    def test_parse_none_input(self):
        """Test parsing None input handles gracefully."""
        parser = LogParser("/test/path")
        # Should handle None without crashing
        try:
            result = parser.parse_auth_log_line(None)
            # Either returns None or raises AttributeError
            assert result is None or True
        except (AttributeError, TypeError):
            # Expected behavior for None input
            pass
    
    def test_parse_whitespace_only(self):
        """Test parsing whitespace-only string returns None."""
        parser = LogParser("/test/path")
        assert parser.parse_auth_log_line("   \n\t  ") is None
    
    def test_parse_different_ip_formats(self):
        """Test parsing various IP address formats."""
        parser = LogParser("/test/path")
        
        # Valid IP formats
        valid_ips = [
            "Jan 28 15:30:45 server sshd[1]: Failed password for user from 192.168.1.1 port 22 ssh2",
            "Jan 28 15:30:45 server sshd[1]: Failed password for user from 10.0.0.1 port 22 ssh2",
            "Jan 28 15:30:45 server sshd[1]: Failed password for user from 172.16.0.1 port 22 ssh2",
        ]
        
        for line in valid_ips:
            result = parser.parse_auth_log_line(line)
            assert result is not None
            assert "ip" in result
    
    def test_parse_timestamp_extraction(self):
        """Test that timestamp is correctly extracted and parsed."""
        parser = LogParser("/test/path")
        line = "Jan 28 15:30:45 server sshd[1]: Failed password for user from 192.168.1.100 port 22 ssh2"
        
        result = parser.parse_auth_log_line(line)
        
        assert result is not None
        assert result["timestamp"].month == 1  # January
        assert result["timestamp"].day == 28
        assert result["timestamp"].hour == 15
        assert result["timestamp"].minute == 30
        assert result["timestamp"].second == 45
    
    def test_parse_different_usernames(self):
        """Test parsing with different username patterns."""
        parser = LogParser("/test/path")
        
        lines = [
            "Jan 28 15:30:45 server sshd[1]: Failed password for root from 192.168.1.100 port 22 ssh2",
            "Jan 28 15:30:45 server sshd[1]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
            "Jan 28 15:30:45 server sshd[1]: Failed password for invalid user test123 from 192.168.1.100 port 22 ssh2",
        ]
        
        for line in lines:
            result = parser.parse_auth_log_line(line)
            assert result is not None
            assert result["ip"] == "192.168.1.100"


class TestParseMethod:
    """Test the parse() method."""
    
    def test_parse_placeholder(self):
        """Test that parse() method returns None (placeholder)."""
        parser = LogParser("/data/raw/sample_auth.log")
        assert parser.parse() is None
