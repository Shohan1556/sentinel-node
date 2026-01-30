"""
SentinelNode: Secure Centralized Logging & Audit System
Main entry point for the SSH brute-force detection system.
"""

from src.log_parser import LogParser
from src.anomaly_detector import BruteForceDetector
from src.alert_manager import AlertManager
from src.config import CONFIG, DB_CONFIG, is_db_configured
from src.db_connector import DatabaseConnector
from src.data_loader import CICIDS2017Loader
from src.ssh_detector import SSHBruteForceDetector
import logging
import os
import argparse
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def setup_db_connection():
    """Initialize and return database connector if configured."""
    if is_db_configured():
        try:
            logger.info("Database configuration detected. Initializing connection...")
            db_connector = DatabaseConnector(
                host=DB_CONFIG["host"],
                port=DB_CONFIG["port"],
                database=DB_CONFIG["database"],
                user=DB_CONFIG["user"],
                password=DB_CONFIG["password"],
                ssl_mode=DB_CONFIG["ssl_mode"]
            )
            
            if db_connector.test_connection():
                logger.info("✓ Database connection successful")
                return db_connector
            else:
                logger.warning("Database connection test failed. Continuing without database.")
                return None
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            logger.warning("Continuing without database persistence.")
            return None
    return None

def process_log_file(file_path, alert_manager):
    """Process standard auth.log file."""
    logger.info(f"Processing log file (Legacy Mode): {file_path}")
    
    parser = LogParser(file_path)
    detector = BruteForceDetector(
        threshold=CONFIG["threshold"],
        window_minutes=2
    )
    
    alerts_generated = 0
    try:
        with open(file_path, "r") as f:
            for line in f:
                event = parser.parse_auth_log_line(line)
                if event:
                    is_attack = detector.report_attempt(
                        event["ip"], event["timestamp"]
                    )
                    if is_attack:
                        alert_message = (
                            f"[ALERT] SSH-BruteForce from {event['ip']} "
                            f"at {event['timestamp']}"
                        )
                        
                        alert_manager.send_alert(
                            message=alert_message,
                            timestamp=event["timestamp"],
                            source_ip=event["ip"],
                            event_type="SSH-BruteForce",
                            dataset_source="AuthLog"
                        )
                        alerts_generated += 1
                        
    except Exception as e:
        logger.error(f"Error processing log file: {e}")
        print(f"\n❌ Error: {e}")
        
    return alerts_generated

def process_cicids2017_csv(file_path, alert_manager):
    """Process CICIDS2017 CSV file."""
    logger.info(f"Processing CICIDS2017 CSV: {file_path}")
    
    loader = CICIDS2017Loader(file_path)
    # Using same parameters as Khan & Rahman (2023)
    detector = SSHBruteForceDetector(threshold=5, window_minutes=2)
    
    alerts_generated = 0
    
    try:
        # Process in chunks
        for chunk_df in loader.load_and_filter(target_label="SSH-BruteForce"):
            attacks = detector.detect(chunk_df)
            
            for attack in attacks:
                detection_time = attack['detection_time']
                source_ip = attack['source_ip']
                
                alert_message = (
                    f"[ALERT] SSH-BruteForce from {source_ip} "
                    f"at {detection_time}"
                )
                
                alert_manager.send_alert(
                    message=alert_message,
                    timestamp=detection_time,
                    source_ip=source_ip,
                    event_type="SSH-BruteForce",
                    dataset_source="CICIDS2017"
                )
                alerts_generated += 1
                
        if alerts_generated == 0:
            logger.warning("No SSH-BruteForce attacks detected. This might be due to using a benign dataset file.")
            
    except Exception as e:
        logger.error(f"Error processing CSV: {e}")
        print(f"\n❌ Error: {e}")
        
    return alerts_generated

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="SentinelNode: SSH Brute-Force Detection System")
    parser.add_argument("--mode", choices=["csv", "log"], default="log", help="Operation mode: 'csv' for CICIDS2017, 'log' for auth.log")
    parser.add_argument("--input", help="Input file path")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SentinelNode: Secure Centralized Logging & Audit")
    print("=" * 60)
    logger.info(f"Sentinel Node starting in {args.mode.upper()} mode...")
    
    # default paths
    if not args.input:
        if args.mode == "csv":
            args.input = "data/raw/Benign-Monday-WorkingHours.pcap_ISCX.csv"
        else:
            args.input = CONFIG["log_path"]
            
    if not os.path.exists(args.input):
        logger.error(f"Input file not found: {args.input}")
        print(f"\n❌ Error: Input file not found at {args.input}")
        return

    # Initialize components
    db_connector = setup_db_connection()
    alert_manager = AlertManager(
        csv_output_path=CONFIG["alert_output"],
        db_connector=db_connector
    )
    
    alerts_count = 0
    
    try:
        if args.mode == "csv":
            alerts_count = process_cicids2017_csv(args.input, alert_manager)
        else:
            alerts_count = process_log_file(args.input, alert_manager)
            
        # Summary
        print("\n" + "=" * 60)
        print(f"Analysis Complete: {alerts_count} brute-force attack(s) detected")
        print("=" * 60)
        
        if alerts_count > 0:
            print(f"\n✓ Alerts saved to: {CONFIG['alert_output']}")
            if db_connector:
                print(f"✓ Alerts stored in database")
                
    finally:
        if db_connector:
            db_connector.close()

if __name__ == "__main__":
    main()
