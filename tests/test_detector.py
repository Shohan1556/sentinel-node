from src.anomaly_detector import BruteForceDetector
from datetime import datetime, timedelta

def test_brute_force_detection():
    detector = BruteForceDetector(threshold=3, window_minutes=1)
    base = datetime(2026, 1, 20, 15, 0, 0)
    
    # 3 attempts within 1 minute → should alert
    assert not detector.report_attempt("1.1.1.1", base)
    assert not detector.report_attempt("1.1.1.1", base + timedelta(seconds=20))
    assert detector.report_attempt("1.1.1.1", base + timedelta(seconds=50))  # ALERT!

def test_no_alert_outside_window():
    detector = BruteForceDetector(threshold=2, window_minutes=1)
    base = datetime(2026, 1, 20, 15, 0, 0)
    assert not detector.report_attempt("2.2.2.2", base)
    assert not detector.report_attempt("2.2.2.2", base + timedelta(minutes=2))  # Too late