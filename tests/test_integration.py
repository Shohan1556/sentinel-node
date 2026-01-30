"""
Integration tests for SentinelNode.

Tests end-to-end workflows and component interactions.
"""

import pytest
import os
import csv
from datetime import datetime, timedelta
from src.log_parser import LogParser
from src.anomaly_detector import BruteForceDetector
from src.alert_manager import AlertManager
from src.config import CONFIG


class TestEndToEndLogProcessing:
    """Test complete log processing workflow."""
    
    def test_parse_detect_alert_workflow(self, sample_log_file, temp_csv_file, capsys):
        """Test complete workflow: parse logs → detect attacks → generate alerts."""
        # Initialize components
        parser = LogParser(sample_log_file)
        detector = BruteForceDetector(threshold=5, window_minutes=2)
        alert_manager = AlertManager(csv_output_path=temp_csv_file)
        
        alerts = []
        
        # Process log file
        with open(sample_log_file, 'r') as f:
            for line in f:
                event = parser.parse_auth_log_line(line)
                if event:
                    is_attack = detector.report_attempt(
                        event["ip"], event["timestamp"]
                    )
                    if is_attack:
                        alert_message = (
                            f"[ALERT] Brute-force detected from "
                            f"{event['ip']} at {event['timestamp']}"
                        )
                        
                        alert_manager.send_alert(
                            message=alert_message,
                            timestamp=event["timestamp"],
                            source_ip=event["ip"],
                            event_type="brute_force",
                            dataset_source="AuthLog"
                        )
                        
                        alerts.append(alert_message)
        
        # Verify alerts were generated
        assert len(alerts) > 0, "Expected at least one brute-force alert"
        
        # Verify console output
        captured = capsys.readouterr()
        assert "ALERT" in captured.out
        
        # Verify CSV output
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            csv_alerts = list(reader)
        
        assert len(csv_alerts) > 0
        assert csv_alerts[0]['event_type'] == 'brute_force'
    
    def test_multiple_ips_concurrent_attacks(self, temp_dir, temp_csv_file):
        """Test handling multiple concurrent attacks from different IPs."""
        # Create log file with multiple attackers
        log_path = os.path.join(temp_dir, "multi_attack.log")
        
        base_time = "Jan 28 14:00"
        log_content = []
        
        # IP 1: 6 attempts (should trigger)
        for i in range(6):
            log_content.append(
                f"{base_time}:{i:02d} server sshd[100{i}]: Failed password for admin from 192.168.1.100 port 22 ssh2"
            )
        
        # IP 2: 3 attempts (should not trigger with threshold=5)
        for i in range(3):
            log_content.append(
                f"{base_time}:{10+i:02d} server sshd[200{i}]: Failed password for root from 10.0.0.50 port 22 ssh2"
            )
        
        # IP 3: 5 attempts (should trigger)
        for i in range(5):
            log_content.append(
                f"{base_time}:{20+i:02d} server sshd[300{i}]: Failed password for test from 172.16.0.25 port 22 ssh2"
            )
        
        with open(log_path, 'w') as f:
            f.write('\n'.join(log_content))
        
        # Process logs
        parser = LogParser(log_path)
        detector = BruteForceDetector(threshold=5, window_minutes=2)
        alert_manager = AlertManager(csv_output_path=temp_csv_file)
        
        detected_ips = set()
        
        with open(log_path, 'r') as f:
            for line in f:
                event = parser.parse_auth_log_line(line)
                if event:
                    is_attack = detector.report_attempt(event["ip"], event["timestamp"])
                    if is_attack:
                        detected_ips.add(event["ip"])
                        alert_manager.send_alert(
                            message=f"Attack from {event['ip']}",
                            timestamp=event["timestamp"],
                            source_ip=event["ip"],
                            event_type="brute_force"
                        )
        
        # Verify correct IPs were detected
        assert "192.168.1.100" in detected_ips
        assert "172.16.0.25" in detected_ips
        assert "10.0.0.50" not in detected_ips  # Only 3 attempts
    
    def test_time_window_expiration_integration(self, temp_dir, temp_csv_file):
        """Test that time window expiration works in full workflow."""
        log_path = os.path.join(temp_dir, "window_test.log")
        
        # Create logs with attempts spread over time
        log_content = [
            "Jan 28 14:00:00 server sshd[1001]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            "Jan 28 14:00:30 server sshd[1002]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            "Jan 28 14:01:00 server sshd[1003]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            # Long gap - previous attempts should expire
            "Jan 28 14:05:00 server sshd[1004]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            "Jan 28 14:05:30 server sshd[1005]: Failed password for admin from 192.168.1.100 port 22 ssh2",
        ]
        
        with open(log_path, 'w') as f:
            f.write('\n'.join(log_content))
        
        parser = LogParser(log_path)
        detector = BruteForceDetector(threshold=5, window_minutes=2)
        alert_manager = AlertManager(csv_output_path=temp_csv_file)
        
        alert_count = 0
        
        with open(log_path, 'r') as f:
            for line in f:
                event = parser.parse_auth_log_line(line)
                if event:
                    is_attack = detector.report_attempt(event["ip"], event["timestamp"])
                    if is_attack:
                        alert_count += 1
        
        # Should not trigger alert (max 3 attempts in any 2-minute window)
        assert alert_count == 0


class TestAlertManagerIntegration:
    """Test AlertManager integration with multiple outputs."""
    
    def test_multi_channel_alert_consistency(self, temp_csv_file, mock_db_connector, capsys):
        """Test that alerts are consistent across all channels."""
        alert_manager = AlertManager(
            csv_output_path=temp_csv_file,
            db_connector=mock_db_connector
        )
        
        test_timestamp = datetime(2026, 1, 28, 15, 30, 45)
        test_ip = "192.168.1.100"
        
        alert_manager.send_alert(
            message="Test multi-channel alert",
            timestamp=test_timestamp,
            source_ip=test_ip,
            event_type="brute_force",
            dataset_source="Testing"
        )
        
        # Verify console
        captured = capsys.readouterr()
        assert "Test multi-channel alert" in captured.out
        
        # Verify CSV
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            csv_rows = list(reader)
        
        assert len(csv_rows) == 1
        assert csv_rows[0]['source_ip'] == test_ip
        
        
        # Verify database
        db_call_args = mock_db_connector.insert_alert.call_args[1]
        assert db_call_args['source_ip'] == test_ip
    
    def test_csv_persistence_across_multiple_alerts(self, temp_csv_file):
        """Test that CSV file accumulates alerts correctly."""
        alert_manager = AlertManager(csv_output_path=temp_csv_file)
        
        # Send multiple alerts
        for i in range(5):
            alert_manager.send_alert(
                message=f"Alert {i}",
                timestamp=datetime(2026, 1, 28, 15, 30, i),
                source_ip=f"192.168.1.{100 + i}",
                event_type="brute_force"
            )
        
        # Verify all alerts are in CSV
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 5
        
        # Verify order and content
        for i, row in enumerate(rows):
            assert row['source_ip'] == f"192.168.1.{100 + i}"


class TestMainApplicationFlow:
    """Test main application workflow simulation."""
    
    def test_main_workflow_simulation(self, sample_log_file, temp_csv_file):
        """Simulate the main application workflow."""
        # This mimics what main.py does
        parser = LogParser(sample_log_file)
        detector = BruteForceDetector(
            threshold=CONFIG["threshold"],
            window_minutes=2
        )
        alert_manager = AlertManager(csv_output_path=temp_csv_file)
        
        alerts = []
        
        # Process log file
        with open(sample_log_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                event = parser.parse_auth_log_line(line)
                if event:
                    is_attack = detector.report_attempt(
                        event["ip"], event["timestamp"]
                    )
                    if is_attack:
                        alert_message = (
                            f"[ALERT] Brute-force detected from "
                            f"{event['ip']} at {event['timestamp']}"
                        )
                        
                        alert_manager.send_alert(
                            message=alert_message,
                            timestamp=event["timestamp"],
                            source_ip=event["ip"],
                            event_type="brute_force",
                            dataset_source="AuthLog"
                        )
                        
                        alerts.append(alert_message)
        
        # Verify workflow completed successfully
        assert isinstance(alerts, list)
        
        # If alerts were generated, verify they're in CSV
        if alerts:
            with open(temp_csv_file, 'r') as f:
                reader = csv.DictReader(f)
                csv_alerts = list(reader)
            assert len(csv_alerts) == len(alerts)
    
    def test_empty_log_file_handling(self, temp_dir, temp_csv_file):
        """Test handling of empty log file."""
        empty_log = os.path.join(temp_dir, "empty.log")
        
        # Create empty file
        open(empty_log, 'w').close()
        
        parser = LogParser(empty_log)
        detector = BruteForceDetector(threshold=5, window_minutes=2)
        alert_manager = AlertManager(csv_output_path=temp_csv_file)
        
        alerts = []
        
        with open(empty_log, 'r') as f:
            for line in f:
                event = parser.parse_auth_log_line(line)
                if event:
                    is_attack = detector.report_attempt(event["ip"], event["timestamp"])
                    if is_attack:
                        alerts.append("alert")
        
        # Should handle gracefully with no alerts
        assert len(alerts) == 0
        
        # CSV should only have headers
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 0
    
    def test_log_file_with_no_failed_logins(self, temp_dir, temp_csv_file):
        """Test log file with only successful logins."""
        log_path = os.path.join(temp_dir, "success_only.log")
        
        log_content = [
            "Jan 28 14:00:00 server sshd[1001]: Accepted password for user1 from 192.168.1.100 port 22 ssh2",
            "Jan 28 14:01:00 server sshd[1002]: Accepted password for user2 from 192.168.1.101 port 22 ssh2",
            "Jan 28 14:02:00 server sshd[1003]: Accepted password for user3 from 192.168.1.102 port 22 ssh2",
        ]
        
        with open(log_path, 'w') as f:
            f.write('\n'.join(log_content))
        
        parser = LogParser(log_path)
        detector = BruteForceDetector(threshold=5, window_minutes=2)
        alert_manager = AlertManager(csv_output_path=temp_csv_file)
        
        alerts = []
        
        with open(log_path, 'r') as f:
            for line in f:
                event = parser.parse_auth_log_line(line)
                if event:
                    is_attack = detector.report_attempt(event["ip"], event["timestamp"])
                    if is_attack:
                        alerts.append("alert")
        
        # No failed logins = no alerts
        assert len(alerts) == 0


class TestComponentInteractions:
    """Test interactions between different components."""
    
    def test_parser_detector_integration(self):
        """Test LogParser and BruteForceDetector working together."""
        parser = LogParser("/test/path")
        detector = BruteForceDetector(threshold=3, window_minutes=1)
        
        # Sample log lines with rapid failed attempts
        log_lines = [
            "Jan 28 15:00:00 server sshd[1]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            "Jan 28 15:00:10 server sshd[2]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            "Jan 28 15:00:20 server sshd[3]: Failed password for admin from 192.168.1.100 port 22 ssh2",
        ]
        
        attack_detected = False
        
        for line in log_lines:
            event = parser.parse_auth_log_line(line)
            if event:
                is_attack = detector.report_attempt(event["ip"], event["timestamp"])
                if is_attack:
                    attack_detected = True
        
        assert attack_detected == True
    
    def test_detector_alert_manager_integration(self, temp_csv_file):
        """Test BruteForceDetector and AlertManager working together."""
        detector = BruteForceDetector(threshold=2, window_minutes=1)
        alert_manager = AlertManager(csv_output_path=temp_csv_file)
        
        base_time = datetime(2026, 1, 28, 15, 0, 0)
        test_ip = "192.168.1.100"
        
        # Simulate attempts
        for i in range(3):
            timestamp = base_time + timedelta(seconds=i * 10)
            is_attack = detector.report_attempt(test_ip, timestamp)
            
            if is_attack:
                alert_manager.send_alert(
                    message=f"Attack from {test_ip}",
                    timestamp=timestamp,
                    source_ip=test_ip,
                    event_type="brute_force"
                )
        
        # Verify alert was logged
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        # Should have at least one alert (2nd and 3rd attempts)
        assert len(rows) >= 1
        assert rows[0]['source_ip'] == test_ip

class TestCICIDS2017Integration:
    """Test CICIDS2017 specific workflows."""
    
    def test_csv_processing_e2e(self, tmp_path, temp_csv_file):
        """Test end-to-end processing of a sample CICIDS2017 CSV."""
        import sys
        import os
        sys.path.append(os.getcwd())
        from main import process_cicids2017_csv
        from src.alert_manager import AlertManager
        import pandas as pd
        from datetime import datetime
        
        # Create sample CSV with attacks
        csv_path = tmp_path / "test_attack.csv"
        
        # 5 attacks in < 2 mins -> Trigger
        base = datetime(2017, 7, 3, 10, 0, 0)
        data = []
        for i in range(5):
            data.append({
                " Source IP": "192.168.1.50",
                " Destination Port": 22,
                " Protocol": 6,
                " Timestamp": (base + timedelta(seconds=i*10)).strftime("%d/%m/%Y %H:%M"),
                " Label": "SSH-BruteForce"
            })
            
        pd.DataFrame(data).to_csv(csv_path, index=False)
        
        # Process
        alert_manager = AlertManager(csv_output_path=str(temp_csv_file))
        
        count = process_cicids2017_csv(str(csv_path), alert_manager)
        
        assert count > 0
        
        # Verify CSV output
        with open(temp_csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
        assert len(rows) > 0
        assert rows[0]['dataset_source'] == 'CICIDS2017'
        assert rows[0]['source_ip'] == '192.168.1.50'
