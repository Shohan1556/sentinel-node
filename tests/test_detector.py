"""
Unit tests for BruteForceDetector module.

Tests brute-force detection logic including threshold detection,
time window validation, and multiple IP tracking.
"""

import sys
import os

# Add src to path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.anomaly_detector import BruteForceDetector
from datetime import datetime, timedelta
import pytest


class TestBruteForceDetectorInitialization:
    """Test BruteForceDetector initialization."""
    
    def test_default_initialization(self):
        """Test detector initializes with default values."""
        detector = BruteForceDetector()
        assert detector.threshold == 5
        assert detector.window == timedelta(minutes=2)
    
    def test_custom_threshold(self):
        """Test detector with custom threshold."""
        detector = BruteForceDetector(threshold=3)
        assert detector.threshold == 3
    
    def test_custom_window(self):
        """Test detector with custom time window."""
        detector = BruteForceDetector(window_minutes=5)
        assert detector.window == timedelta(minutes=5)
    
    def test_custom_threshold_and_window(self):
        """Test detector with both custom threshold and window."""
        detector = BruteForceDetector(threshold=10, window_minutes=3)
        assert detector.threshold == 10
        assert detector.window == timedelta(minutes=3)


class TestThresholdDetection:
    """Test threshold-based brute-force detection."""
    
    def test_brute_force_detection_success(self):
        """Test that alert triggers when threshold is reached within time window."""
        detector = BruteForceDetector(threshold=5, window_minutes=2)
        base_time = datetime(2026, 1, 20, 14, 0, 0)

        # Simulate 5 failed attempts within 90 seconds
        for i in range(5):
            event_time = base_time + timedelta(seconds=i * 20)  # 0s, 20s, 40s, 60s, 80s
            is_alert = detector.report_attempt("192.168.1.100", event_time)
            if i < 4:
                assert is_alert == False, f"Alert triggered too early at attempt {i+1}"
            else:
                assert is_alert == True, "Expected alert on 5th attempt within window"
    
    def test_threshold_exactly_met(self):
        """Test behavior when exactly meeting threshold."""
        detector = BruteForceDetector(threshold=3, window_minutes=1)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # First two attempts should not trigger
        assert detector.report_attempt("10.0.0.1", base_time) == False
        assert detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=10)) == False
        
        # Third attempt should trigger
        assert detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=20)) == True
    
    def test_threshold_exceeded(self):
        """Test that alerts continue after threshold is exceeded."""
        detector = BruteForceDetector(threshold=3, window_minutes=2)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # First 3 attempts
        for i in range(3):
            detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=i * 10))
        
        # 4th and 5th attempts should also trigger alerts
        assert detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=40)) == True
        assert detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=50)) == True


class TestTimeWindowValidation:
    """Test time window expiration and validation."""
    
    def test_no_alert_outside_window(self):
        """Test that no alert is triggered when attempts are outside time window."""
        detector = BruteForceDetector(threshold=5, window_minutes=2)
        base_time = datetime(2026, 1, 20, 14, 0, 0)

        # First attempt
        assert detector.report_attempt("10.0.0.50", base_time) == False

        # Second attempt after 1 minute
        assert detector.report_attempt("10.0.0.50", base_time + timedelta(minutes=1)) == False

        # Third attempt after 2 minutes
        assert detector.report_attempt("10.0.0.50", base_time + timedelta(minutes=2)) == False

        # Fourth attempt after 3 minutes → first attempt is now expired
        assert detector.report_attempt("10.0.0.50", base_time + timedelta(minutes=3)) == False
    
    def test_window_expiration(self):
        """Test that old attempts are removed from the window."""
        detector = BruteForceDetector(threshold=3, window_minutes=1)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # Two attempts within window
        detector.report_attempt("10.0.0.1", base_time)
        detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=30))
        
        # Third attempt after 2 minutes (first two should be expired)
        result = detector.report_attempt("10.0.0.1", base_time + timedelta(minutes=2))
        assert result == False, "Should not trigger alert as previous attempts expired"
    
    def test_window_boundary(self):
        """Test behavior at exact window boundary."""
        detector = BruteForceDetector(threshold=3, window_minutes=2)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # Attempt at time 0
        detector.report_attempt("10.0.0.1", base_time)
        
        # Attempt at exactly 2 minutes (boundary)
        detector.report_attempt("10.0.0.1", base_time + timedelta(minutes=2))
        
        # Attempt just after 2 minutes
        result = detector.report_attempt("10.0.0.1", base_time + timedelta(minutes=2, seconds=1))
        
        # Should not trigger as first attempt is now outside window
        assert result == False


class TestMultipleIPTracking:
    """Test tracking multiple IPs simultaneously."""
    
    def test_different_ips_tracked_separately(self):
        """Test that different IPs are tracked independently."""
        detector = BruteForceDetector(threshold=3, window_minutes=2)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # IP1: 2 attempts
        detector.report_attempt("192.168.1.100", base_time)
        detector.report_attempt("192.168.1.100", base_time + timedelta(seconds=10))
        
        # IP2: 2 attempts
        detector.report_attempt("10.0.0.50", base_time)
        detector.report_attempt("10.0.0.50", base_time + timedelta(seconds=10))
        
        # IP1: 3rd attempt should trigger
        assert detector.report_attempt("192.168.1.100", base_time + timedelta(seconds=20)) == True
        
        # IP2: 3rd attempt should also trigger (now has 3 attempts)
        assert detector.report_attempt("10.0.0.50", base_time + timedelta(seconds=20)) == True
    
    def test_concurrent_attacks_from_multiple_ips(self):
        """Test handling concurrent attacks from multiple sources."""
        detector = BruteForceDetector(threshold=3, window_minutes=1)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25"]
        
        # Each IP makes 3 attempts
        for i in range(3):
            for ip in ips:
                result = detector.report_attempt(ip, base_time + timedelta(seconds=i * 10))
                if i == 2:  # Third attempt
                    assert result == True, f"Expected alert for {ip} on 3rd attempt"
                else:
                    assert result == False


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_rapid_sequential_attempts(self):
        """Test very rapid sequential attempts (same second)."""
        detector = BruteForceDetector(threshold=5, window_minutes=1)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # 5 attempts in the same second
        for i in range(5):
            result = detector.report_attempt("192.168.1.100", base_time)
            if i < 4:
                assert result == False
            else:
                assert result == True
    
    def test_single_attempt_no_alert(self):
        """Test that single attempt never triggers alert."""
        detector = BruteForceDetector(threshold=5, window_minutes=2)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        result = detector.report_attempt("192.168.1.100", base_time)
        assert result == False
    
    def test_threshold_one(self):
        """Test detector with threshold of 1."""
        detector = BruteForceDetector(threshold=1, window_minutes=1)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # First attempt should trigger
        result = detector.report_attempt("192.168.1.100", base_time)
        assert result == True
    
    def test_attempts_at_window_edges(self):
        """Test attempts at the very edges of the time window."""
        detector = BruteForceDetector(threshold=2, window_minutes=1)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # Attempt at start of window
        detector.report_attempt("10.0.0.1", base_time)
        
        # Attempt at end of window (59 seconds later)
        result = detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=59))
        assert result == True, "Both attempts should be within 1-minute window"
    
    def test_empty_ip_string(self):
        """Test handling of empty IP string."""
        detector = BruteForceDetector(threshold=3, window_minutes=1)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # Should handle empty string without crashing
        result = detector.report_attempt("", base_time)
        assert result == False
    
    def test_attempts_in_reverse_chronological_order(self):
        """Test that detector handles timestamps not in chronological order."""
        detector = BruteForceDetector(threshold=3, window_minutes=2)
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        
        # Report attempts out of order
        detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=60))
        detector.report_attempt("10.0.0.1", base_time + timedelta(seconds=30))
        result = detector.report_attempt("10.0.0.1", base_time)
        
        # All three are within window, should trigger
        assert result == True