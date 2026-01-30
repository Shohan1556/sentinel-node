"""
Unit tests for SSH Brute-Force Detector.
"""

import pytest
import pandas as pd
from datetime import datetime, timedelta
from src.ssh_detector import SSHBruteForceDetector

class TestSSHBruteForceDetector:
    
    @pytest.fixture
    def detector(self):
        return SSHBruteForceDetector(threshold=5, window_minutes=2)
        
    def test_detection_threshold_triggered(self, detector):
        """Test detection triggers exactly at threshold."""
        # Create 5 events within 1 minute
        base_time = datetime(2017, 7, 3, 10, 0, 0)
        events = []
        for i in range(5):
            events.append({
                'source_ip': '192.168.1.100',
                'timestamp': base_time + timedelta(seconds=i*10),
                'label': 'SSH-BruteForce'
            })
            
        df = pd.DataFrame(events)
        results = detector.detect(df)
        
        assert len(results) > 0
        assert results[0]['source_ip'] == '192.168.1.100'
        # The detection happens on the 5th attempt
        assert results[0]['detection_time'] == events[-1]['timestamp']

    def test_detection_threshold_not_reached(self, detector):
        """Test detection does NOT trigger below threshold."""
        # Create 4 events within 1 minute
        base_time = datetime(2017, 7, 3, 10, 0, 0)
        events = []
        for i in range(4):
            events.append({
                'source_ip': '192.168.1.100',
                'timestamp': base_time + timedelta(seconds=i*10),
                'label': 'SSH-BruteForce'
            })
            
        df = pd.DataFrame(events)
        results = detector.detect(df)
        
        assert len(results) == 0

    def test_time_window_expiration(self, detector):
        """Test events outside window are not counted."""
        base_time = datetime(2017, 7, 3, 10, 0, 0)
        events = [
            # 4 events at T=0
            {'source_ip': '192.168.1.100', 'timestamp': base_time, 'label': 'SSH-BruteForce'},
            {'source_ip': '192.168.1.100', 'timestamp': base_time, 'label': 'SSH-BruteForce'},
            {'source_ip': '192.168.1.100', 'timestamp': base_time, 'label': 'SSH-BruteForce'},
            {'source_ip': '192.168.1.100', 'timestamp': base_time, 'label': 'SSH-BruteForce'},
            
            # 1 event at T=3 minutes (outside 2 min window)
            {'source_ip': '192.168.1.100', 'timestamp': base_time + timedelta(minutes=3), 'label': 'SSH-BruteForce'}
        ]
        
        df = pd.DataFrame(events)
        results = detector.detect(df)
        
        assert len(results) == 0

    def test_multiple_ips(self, detector):
        """Test independent detection for different IPs."""
        base_time = datetime(2017, 7, 3, 10, 0, 0)
        events = []
        
        # IP 1: 5 attempts (Trigger)
        for i in range(5):
            events.append({
                'source_ip': '192.168.1.100', 
                'timestamp': base_time + timedelta(seconds=i),
                'label': 'SSH-BruteForce'
            })
            
        # IP 2: 3 attempts (No Trigger)
        for i in range(3):
            events.append({
                'source_ip': '10.0.0.5', 
                'timestamp': base_time + timedelta(seconds=i),
                'label': 'SSH-BruteForce'
            })
            
        df = pd.DataFrame(events)
        results = detector.detect(df)
        
        detected_ips = {r['source_ip'] for r in results}
        assert '192.168.1.100' in detected_ips
        assert '10.0.0.5' not in detected_ips

    def test_sliding_window_correctness(self, detector):
        """
        Verify the sliding aspect.
        Events at: 0:00, 0:30, 1:00, 1:30, 2:10
        Window 2 mins.
        
        At 2:00 window [0:00, 2:00] contains 4 events.
        At 2:10 window [0:10, 2:10] contains 4 events (0:00 dropped).
        
        So if we add a 5th event at 2:10, it should NOT trigger if 0:00 is > 2 mins ago.
        Wait, window is 2 mins.
        Range [0:10, 2:10] is exactly 2 mins.
        
        Let's be precise:
        Events:
        1. 10:00:00
        2. 10:00:30
        3. 10:01:00
        4. 10:01:30
        5. 10:02:01 (Time diff to #1 is 2 min 1 sec)
        
        Window [10:00:01, 10:02:01]. #1 is excluded. Count is 4. No trigger.
        """
        base = datetime(2017, 7, 3, 10, 0, 0)
        events = [
            {'source_ip': '192.168.1.100', 'timestamp': base},
            {'source_ip': '192.168.1.100', 'timestamp': base + timedelta(seconds=30)},
            {'source_ip': '192.168.1.100', 'timestamp': base + timedelta(seconds=60)},
            {'source_ip': '192.168.1.100', 'timestamp': base + timedelta(seconds=90)},
            {'source_ip': '192.168.1.100', 'timestamp': base + timedelta(seconds=121)}
        ]
        
        df = pd.DataFrame(events)
        results = detector.detect(df)
        
        assert len(results) == 0
        
        # Now add one more at 10:02:05 -> count in [10:00:05, 10:02:05] 
        # includes #2, #3, #4, #5 + new one = 5 events. Trigger!
        events.append(
            {'source_ip': '192.168.1.100', 'timestamp': base + timedelta(seconds=125)}
        )
        
        df = pd.DataFrame(events)
        results = detector.detect(df)
        
        assert len(results) > 0
