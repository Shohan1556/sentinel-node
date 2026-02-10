"""
Comprehensive Test Suite for SentinelNode Detection System

Tests all detection functions with proper metrics:
- Accuracy
- Precision
- Recall
- F1-Score
- Confusion Matrix
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from src.detectors.ssh_detector import SSHBruteForceDetector
from src.detectors.ddos_detector import DDoSDetector
from src.db_connector import create_db_connector_from_env


class DetectionMetrics:
    """Calculate detection performance metrics."""
    
    def __init__(self):
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
    
    def update(self, predicted: bool, actual: bool):
        """Update confusion matrix."""
        if predicted and actual:
            self.true_positives += 1
        elif predicted and not actual:
            self.false_positives += 1
        elif not predicted and actual:
            self.false_negatives += 1
        else:
            self.true_negatives += 1
    
    def accuracy(self) -> float:
        """Calculate accuracy: (TP + TN) / Total"""
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total
    
    def precision(self) -> float:
        """Calculate precision: TP / (TP + FP)"""
        denominator = self.true_positives + self.false_positives
        if denominator == 0:
            return 0.0
        return self.true_positives / denominator
    
    def recall(self) -> float:
        """Calculate recall: TP / (TP + FN)"""
        denominator = self.true_positives + self.false_negatives
        if denominator == 0:
            return 0.0
        return self.true_positives / denominator
    
    def f1_score(self) -> float:
        """Calculate F1-score: 2 * (precision * recall) / (precision + recall)"""
        p = self.precision()
        r = self.recall()
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)
    
    def get_metrics(self) -> Dict[str, float]:
        """Get all metrics as dictionary."""
        return {
            'accuracy': self.accuracy(),
            'precision': self.precision(),
            'recall': self.recall(),
            'f1_score': self.f1_score(),
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives
        }
    
    def print_metrics(self, title: str = "Detection Metrics"):
        """Print formatted metrics."""
        metrics = self.get_metrics()
        print(f"\n{'=' * 70}")
        print(f"{title}")
        print(f"{'=' * 70}")
        print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        print(f"Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        print(f"F1-Score:  {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)")
        print(f"\nConfusion Matrix:")
        print(f"  True Positives:  {metrics['true_positives']}")
        print(f"  False Positives: {metrics['false_positives']}")
        print(f"  True Negatives:  {metrics['true_negatives']}")
        print(f"  False Negatives: {metrics['false_negatives']}")
        print(f"{'=' * 70}")


def generate_ssh_test_data() -> Tuple[pd.DataFrame, List[bool]]:
    """
    Generate synthetic SSH test data with ground truth labels.
    
    Returns:
        Tuple of (DataFrame, ground_truth_labels)
    """
    np.random.seed(42)
    base_time = datetime.now()
    
    data = []
    labels = []  # True = attack, False = benign
    
    # Scenario 1: Clear SSH brute-force attack (30 attempts in 10 minutes)
    attack_ip1 = '10.0.0.100'
    for i in range(30):
        data.append({
            'src_ip': attack_ip1,
            'timestamp': base_time + timedelta(seconds=i*20),
            'Protocol': 6,
            'Total Fwd Packets': 8,
            'Total Backward Packets': 2,
            'Flow Duration': 500000,
            'Label': 'SSH-Patator'
        })
        labels.append(True)  # Attack
    
    # Scenario 2: Benign SSH traffic (5 attempts spread over 30 minutes)
    benign_ip1 = '10.0.0.200'
    for i in range(5):
        data.append({
            'src_ip': benign_ip1,
            'timestamp': base_time + timedelta(minutes=i*6),
            'Protocol': 6,
            'Total Fwd Packets': 5,
            'Total Backward Packets': 4,
            'Flow Duration': 2000000,
            'Label': 'Benign'
        })
        labels.append(False)  # Benign
    
    # Scenario 3: Moderate attack (15 attempts in 5 minutes)
    attack_ip2 = '10.0.0.150'
    for i in range(15):
        data.append({
            'src_ip': attack_ip2,
            'timestamp': base_time + timedelta(seconds=i*20),
            'Protocol': 6,
            'Total Fwd Packets': 10,
            'Total Backward Packets': 1,
            'Flow Duration': 300000,
            'Label': 'SSH-Patator'
        })
        labels.append(True)  # Attack
    
    # Scenario 4: More benign traffic
    benign_ip2 = '10.0.0.250'
    for i in range(8):
        data.append({
            'src_ip': benign_ip2,
            'timestamp': base_time + timedelta(minutes=i*5),
            'Protocol': 6,
            'Total Fwd Packets': 6,
            'Total Backward Packets': 5,
            'Flow Duration': 1500000,
            'Label': 'Benign'
        })
        labels.append(False)  # Benign
    
    return pd.DataFrame(data), labels


def generate_ddos_test_data() -> Tuple[pd.DataFrame, List[bool]]:
    """
    Generate synthetic DDoS test data with ground truth labels.
    
    Returns:
        Tuple of (DataFrame, ground_truth_labels)
    """
    np.random.seed(42)
    base_time = datetime.now()
    
    data = []
    labels = []  # True = attack, False = benign
    
    # Scenario 1: Clear UDP flood attack
    attack_ip1 = '172.16.0.100'
    for i in range(20):
        data.append({
            'src_ip': attack_ip1,
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
        labels.append(True)  # Attack
    
    # Scenario 2: Benign UDP traffic (DNS)
    benign_ip1 = '172.16.0.200'
    for i in range(10):
        data.append({
            'src_ip': benign_ip1,
            'timestamp': base_time + timedelta(seconds=i*2),
            'Protocol': 17,  # UDP
            'Total Fwd Packets': 2,
            'Total Backward Packets': 2,
            'Flow Duration': 100000,
            'Fwd Packet Length Mean': 64,
            'Bwd Packet Length Mean': 128,
            'Flow Packets/s': 40,
            'Destination Port': 53,  # DNS
            'Label': 'Benign'
        })
        labels.append(False)  # Benign
    
    # Scenario 3: SYN flood attack
    attack_ip2 = '172.16.0.150'
    for i in range(15):
        data.append({
            'src_ip': attack_ip2,
            'timestamp': base_time + timedelta(milliseconds=i*100),
            'Protocol': 6,  # TCP
            'Total Fwd Packets': 100,
            'Total Backward Packets': 5,
            'Flow Duration': 80000,
            'Fwd Packet Length Mean': 64,
            'Bwd Packet Length Mean': 40,
            'Flow Packets/s': 1250,
            'Destination Port': 80,
            'Label': 'DDoS'
        })
        labels.append(True)  # Attack
    
    # Scenario 4: Normal web traffic
    benign_ip2 = '172.16.0.250'
    for i in range(12):
        data.append({
            'src_ip': benign_ip2,
            'timestamp': base_time + timedelta(seconds=i*3),
            'Protocol': 6,  # TCP
            'Total Fwd Packets': 10,
            'Total Backward Packets': 8,
            'Flow Duration': 500000,
            'Fwd Packet Length Mean': 256,
            'Bwd Packet Length Mean': 512,
            'Flow Packets/s': 36,
            'Destination Port': 443,
            'Label': 'Benign'
        })
        labels.append(False)  # Benign
    
    return pd.DataFrame(data), labels


def test_ssh_detector():
    """Test SSH detector with metrics validation."""
    print("\n" + "=" * 70)
    print("TEST 1: SSH Brute-Force Detector with Metrics")
    print("=" * 70)
    
    # Generate test data
    df, ground_truth = generate_ssh_test_data()
    print(f"\nGenerated test dataset:")
    print(f"  Total flows: {len(df)}")
    print(f"  Attack flows: {sum(ground_truth)}")
    print(f"  Benign flows: {len(ground_truth) - sum(ground_truth)}")
    
    # Initialize detector
    db = create_db_connector_from_env()
    detector = SSHBruteForceDetector(db_connector=db)
    
    # Run detection
    detections = detector.detect(df)
    
    # Create IP-level predictions
    detected_ips = set(d['src_ip'] for d in detections)
    
    # Calculate metrics at flow level
    metrics = DetectionMetrics()
    
    for idx, row in df.iterrows():
        predicted = row['src_ip'] in detected_ips
        actual = ground_truth[idx]
        metrics.update(predicted, actual)
    
    # Print results
    print(f"\nDetection Results:")
    print(f"  Total detections: {len(detections)}")
    print(f"  Unique attacking IPs detected: {len(detected_ips)}")
    
    metrics.print_metrics("SSH Detector Performance Metrics")
    
    if db:
        db.close()
    
    return metrics.get_metrics()


def test_ddos_detector():
    """Test DDoS detector with metrics validation."""
    print("\n" + "=" * 70)
    print("TEST 2: DDoS Detector with Metrics")
    print("=" * 70)
    
    # Generate test data
    df, ground_truth = generate_ddos_test_data()
    print(f"\nGenerated test dataset:")
    print(f"  Total flows: {len(df)}")
    print(f"  Attack flows: {sum(ground_truth)}")
    print(f"  Benign flows: {len(ground_truth) - sum(ground_truth)}")
    
    # Initialize detector
    db = create_db_connector_from_env()
    detector = DDoSDetector(db_connector=db)
    
    # Set baseline stats
    baseline_stats = {
        'global_mean_pps': 50.0,
        'global_std_pps': 20.0,
        'global_95th_pps': 100.0
    }
    detector.set_baseline_stats(baseline_stats)
    
    # Run detection
    detections = detector.detect(df)
    
    # Create IP-level predictions
    detected_ips = set(d['src_ip'] for d in detections)
    
    # Calculate metrics at flow level
    metrics = DetectionMetrics()
    
    for idx, row in df.iterrows():
        predicted = row['src_ip'] in detected_ips
        actual = ground_truth[idx]
        metrics.update(predicted, actual)
    
    # Print results
    print(f"\nDetection Results:")
    print(f"  Total detections: {len(detections)}")
    print(f"  Unique attacking IPs detected: {len(detected_ips)}")
    
    metrics.print_metrics("DDoS Detector Performance Metrics")
    
    if db:
        db.close()
    
    return metrics.get_metrics()


def test_combined_system():
    """Test combined SSH + DDoS detection system."""
    print("\n" + "=" * 70)
    print("TEST 3: Combined Detection System")
    print("=" * 70)
    
    # Generate combined dataset
    ssh_df, ssh_labels = generate_ssh_test_data()
    ddos_df, ddos_labels = generate_ddos_test_data()
    
    combined_df = pd.concat([ssh_df, ddos_df], ignore_index=True)
    combined_labels = ssh_labels + ddos_labels
    
    print(f"\nCombined test dataset:")
    print(f"  Total flows: {len(combined_df)}")
    print(f"  Attack flows: {sum(combined_labels)}")
    print(f"  Benign flows: {len(combined_labels) - sum(combined_labels)}")
    
    # Initialize detectors
    db = create_db_connector_from_env()
    ssh_detector = SSHBruteForceDetector(db_connector=db)
    ddos_detector = DDoSDetector(db_connector=db)
    
    # Set baseline for DDoS
    baseline_stats = {
        'global_mean_pps': 50.0,
        'global_std_pps': 20.0,
        'global_95th_pps': 100.0
    }
    ddos_detector.set_baseline_stats(baseline_stats)
    
    # Run both detectors
    ssh_detections = ssh_detector.detect(ssh_df)
    ddos_detections = ddos_detector.detect(ddos_df)
    
    # Combine detected IPs
    ssh_detected_ips = set(d['src_ip'] for d in ssh_detections)
    ddos_detected_ips = set(d['src_ip'] for d in ddos_detections)
    all_detected_ips = ssh_detected_ips | ddos_detected_ips
    
    # Calculate metrics
    metrics = DetectionMetrics()
    
    for idx, row in combined_df.iterrows():
        predicted = row['src_ip'] in all_detected_ips
        actual = combined_labels[idx]
        metrics.update(predicted, actual)
    
    # Print results
    print(f"\nDetection Results:")
    print(f"  SSH detections: {len(ssh_detections)}")
    print(f"  DDoS detections: {len(ddos_detections)}")
    print(f"  Total unique attacking IPs: {len(all_detected_ips)}")
    
    metrics.print_metrics("Combined System Performance Metrics")
    
    if db:
        db.close()
    
    return metrics.get_metrics()


def main():
    """Run all tests."""
    print("=" * 70)
    print("SentinelNode Comprehensive Test Suite")
    print("Testing with Accuracy, Precision, Recall, F1-Score")
    print("=" * 70)
    
    results = {}
    
    try:
        # Test SSH detector
        results['ssh'] = test_ssh_detector()
        
        # Test DDoS detector
        results['ddos'] = test_ddos_detector()
        
        # Test combined system
        results['combined'] = test_combined_system()
        
        # Print summary
        print("\n" + "=" * 70)
        print("OVERALL TEST SUMMARY")
        print("=" * 70)
        
        for test_name, metrics in results.items():
            print(f"\n{test_name.upper()} Detector:")
            print(f"  Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
            print(f"  Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
            print(f"  Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
            print(f"  F1-Score:  {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)")
        
        print("\n" + "=" * 70)
        print("✅ ALL TESTS COMPLETED SUCCESSFULLY")
        print("=" * 70)
        
        return 0
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
