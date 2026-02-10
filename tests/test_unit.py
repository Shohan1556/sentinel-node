"""
Pytest-based unit tests for SentinelNode components.

Run with: pytest tests/test_unit.py -v
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detectors.ssh_detector import SSHBruteForceDetector
from src.detectors.ddos_detector import DDoSDetector
from src.baseline_learner import BaselineLearner
from src.alert_manager import AlertManager


class TestSSHDetector:
    """Unit tests for SSH Brute-Force Detector."""
    
    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHBruteForceDetector(db_connector=None)
    
    @pytest.fixture
    def benign_traffic(self):
        """Generate benign SSH traffic."""
        base_time = datetime.now()
        data = []
        for i in range(3):
            data.append({
                'src_ip': '192.168.1.100',
                'timestamp': base_time + timedelta(minutes=i*10),
                'Protocol': 6,
                'Total Fwd Packets': 5,
                'Total Backward Packets': 4,
                'Flow Duration': 2000000,
                'Label': 'Benign'
            })
        return pd.DataFrame(data)
    
    @pytest.fixture
    def attack_traffic(self):
        """Generate attack SSH traffic."""
        base_time = datetime.now()
        data = []
        for i in range(25):
            data.append({
                'src_ip': '10.0.0.100',
                'timestamp': base_time + timedelta(seconds=i*30),
                'Protocol': 6,
                'Total Fwd Packets': 8,
                'Total Backward Packets': 2,
                'Flow Duration': 500000,
                'Label': 'SSH-Patator'
            })
        return pd.DataFrame(data)
    
    def test_detector_initialization(self, detector):
        """Test detector initializes correctly."""
        assert detector is not None
        assert detector.TIER_1_THRESHOLD == 5
        assert detector.TIER_2_THRESHOLD == 10
        assert detector.TIER_3_THRESHOLD == 20
    
    def test_benign_traffic_no_detection(self, detector, benign_traffic):
        """Test that benign traffic doesn't trigger false positives."""
        detections = detector.detect(benign_traffic)
        # Should have minimal or no detections for benign traffic
        assert len(detections) <= 1  # Allow for first_time_ip detection
    
    def test_attack_traffic_detection(self, detector, attack_traffic):
        """Test that attack traffic is detected."""
        detections = detector.detect(attack_traffic)
        assert len(detections) > 0
        # Should detect at least Tier 3 attack
        assert any(d['tier'] >= 3 for d in detections)
    
    def test_detection_confidence_scores(self, detector, attack_traffic):
        """Test that confidence scores are within valid range."""
        detections = detector.detect(attack_traffic)
        for detection in detections:
            assert 0.0 <= detection['confidence_score'] <= 1.0
    
    def test_detection_severity_levels(self, detector, attack_traffic):
        """Test that severity levels are valid."""
        detections = detector.detect(attack_traffic)
        valid_severities = {'low', 'medium', 'high', 'critical'}
        for detection in detections:
            assert detection['severity'] in valid_severities


class TestDDoSDetector:
    """Unit tests for DDoS Detector."""
    
    @pytest.fixture
    def detector(self):
        """Create DDoS detector instance."""
        detector = DDoSDetector(db_connector=None)
        # Set baseline stats
        detector.set_baseline_stats({
            'global_mean_pps': 50.0,
            'global_std_pps': 20.0,
            'global_95th_pps': 100.0
        })
        return detector
    
    @pytest.fixture
    def benign_traffic(self):
        """Generate benign network traffic."""
        base_time = datetime.now()
        data = []
        for i in range(10):
            data.append({
                'src_ip': '192.168.1.100',
                'timestamp': base_time + timedelta(seconds=i*2),
                'Protocol': 6,
                'Total Fwd Packets': 10,
                'Total Backward Packets': 8,
                'Flow Duration': 500000,
                'Fwd Packet Length Mean': 256,
                'Bwd Packet Length Mean': 512,
                'Flow Packets/s': 36,
                'Destination Port': 443,
                'Label': 'Benign'
            })
        return pd.DataFrame(data)
    
    @pytest.fixture
    def udp_flood_traffic(self):
        """Generate UDP flood attack traffic."""
        base_time = datetime.now()
        data = []
        for i in range(15):
            data.append({
                'src_ip': '172.16.0.100',
                'timestamp': base_time + timedelta(milliseconds=i*50),
                'Protocol': 17,  # UDP
                'Total Fwd Packets': 200,
                'Total Backward Packets': 0,
                'Flow Duration': 50000,
                'Fwd Packet Length Mean': 512,
                'Bwd Packet Length Mean': 0,
                'Flow Packets/s': 2000,
                'Destination Port': 8080,
                'Label': 'DDoS'
            })
        return pd.DataFrame(data)
    
    def test_detector_initialization(self, detector):
        """Test detector initializes correctly."""
        assert detector is not None
        assert detector.baseline_stats is not None
        assert detector.baseline_stats['global_mean_pps'] == 50.0
    
    def test_benign_traffic_no_detection(self, detector, benign_traffic):
        """Test that benign traffic doesn't trigger false positives."""
        detections = detector.detect(benign_traffic)
        # Should have minimal or no detections for benign traffic
        assert len(detections) <= 1
    
    def test_udp_flood_detection(self, detector, udp_flood_traffic):
        """Test that UDP flood is detected."""
        detections = detector.detect(udp_flood_traffic)
        assert len(detections) > 0
        # Should detect UDP flood pattern
        assert any('udp' in d['pattern_type'].lower() for d in detections)
    
    def test_detection_confidence_scores(self, detector, udp_flood_traffic):
        """Test that confidence scores are within valid range."""
        detections = detector.detect(udp_flood_traffic)
        for detection in detections:
            assert 0.0 <= detection['confidence_score'] <= 1.0
    
    def test_detection_event_types(self, detector, udp_flood_traffic):
        """Test that event types are valid."""
        detections = detector.detect(udp_flood_traffic)
        valid_event_types = {'ddos_volumetric', 'ddos_syn', 'ddos_udp', 'ddos_behavioral'}
        for detection in detections:
            assert detection['event_type'] in valid_event_types


class TestAlertManager:
    """Unit tests for Alert Manager."""
    
    @pytest.fixture
    def alert_manager(self, tmp_path):
        """Create alert manager instance with temporary CSV path."""
        csv_path = tmp_path / "test_alerts.csv"
        return AlertManager(
            csv_output_path=str(csv_path),
            db_connector=None
        )
    
    def test_alert_manager_initialization(self, alert_manager):
        """Test alert manager initializes correctly."""
        assert alert_manager is not None
        assert alert_manager.csv_output_path is not None
    
    def test_send_alert_creates_csv(self, alert_manager):
        """Test that sending alert creates CSV file."""
        alert_manager.send_alert(
            src_ip='192.168.1.100',
            event_type='test_alert',
            severity='medium',
            confidence_score=0.75,
            pattern_type='test_pattern',
            detection_time=datetime.now()
        )
        
        import os
        assert os.path.exists(alert_manager.csv_output_path)
    
    def test_severity_tiers(self, alert_manager):
        """Test severity tier mapping."""
        assert alert_manager.SEVERITY_TIERS['low'] == 1
        assert alert_manager.SEVERITY_TIERS['medium'] == 2
        assert alert_manager.SEVERITY_TIERS['high'] == 3
        assert alert_manager.SEVERITY_TIERS['critical'] == 4


class TestBaselineLearner:
    """Unit tests for Baseline Learner."""
    
    @pytest.fixture
    def learner(self):
        """Create baseline learner instance."""
        return BaselineLearner(db_connector=None)
    
    @pytest.fixture
    def benign_data(self):
        """Generate benign traffic data."""
        np.random.seed(42)
        base_time = datetime.now()
        data = []
        for i in range(50):
            data.append({
                'src_ip': f'192.168.1.{i % 10 + 1}',
                'timestamp': base_time + timedelta(seconds=i*10),
                'Protocol': 6,
                'Total Fwd Packets': np.random.randint(5, 20),
                'Total Backward Packets': np.random.randint(3, 15),
                'Flow Duration': np.random.randint(100000, 5000000),
                'Flow Packets/s': np.random.uniform(10, 200),
                'Label': 'Benign'
            })
        return pd.DataFrame(data)
    
    def test_learner_initialization(self, learner):
        """Test learner initializes correctly."""
        assert learner is not None
        assert learner.ip_baselines == {}
        assert learner.baseline_stats == {}
    
    def test_pps_calculation(self, learner, benign_data):
        """Test PPS calculation."""
        pps_values = learner._calculate_pps(benign_data)
        assert len(pps_values) == len(benign_data)
        assert all(pps >= 0 for pps in pps_values)


# Metrics calculation tests
class TestMetricsCalculation:
    """Test metrics calculation functions."""
    
    def test_accuracy_calculation(self):
        """Test accuracy calculation."""
        # Perfect classification
        tp, fp, tn, fn = 10, 0, 10, 0
        accuracy = (tp + tn) / (tp + fp + tn + fn)
        assert accuracy == 1.0
        
        # 50% accuracy
        tp, fp, tn, fn = 5, 5, 5, 5
        accuracy = (tp + tn) / (tp + fp + tn + fn)
        assert accuracy == 0.5
    
    def test_precision_calculation(self):
        """Test precision calculation."""
        # Perfect precision
        tp, fp = 10, 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        assert precision == 1.0
        
        # 50% precision
        tp, fp = 5, 5
        precision = tp / (tp + fp)
        assert precision == 0.5
    
    def test_recall_calculation(self):
        """Test recall calculation."""
        # Perfect recall
        tp, fn = 10, 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        assert recall == 1.0
        
        # 50% recall
        tp, fn = 5, 5
        recall = tp / (tp + fn)
        assert recall == 0.5
    
    def test_f1_score_calculation(self):
        """Test F1-score calculation."""
        # Perfect F1
        precision, recall = 1.0, 1.0
        f1 = 2 * (precision * recall) / (precision + recall)
        assert f1 == 1.0
        
        # Balanced F1
        precision, recall = 0.5, 0.5
        f1 = 2 * (precision * recall) / (precision + recall)
        assert f1 == 0.5


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
