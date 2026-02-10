"""
SentinelNode: Production-Grade Security Detection System
Main entry point for processing CICIDS2017 datasets and detecting attacks.
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.db_connector import create_db_connector_from_env
from src.alert_manager import AlertManager
from src.data_processor import CICIDS2017Processor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sentinel_node.log')
    ]
)
logger = logging.getLogger(__name__)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SentinelNode: Production-Grade Security Detection System"
    )
    parser.add_argument(
        '--mode',
        choices=['parquet', 'single'],
        default='parquet',
        help='Operation mode: parquet=process all datasets, single=process one file'
    )
    parser.add_argument(
        '--input',
        help='Input file path (for single mode)'
    )
    parser.add_argument(
        '--data-dir',
        default='data/raw/parquet',
        help='Directory containing parquet files (for parquet mode)'
    )
    parser.add_argument(
        '--process-all',
        action='store_true',
        help='Process all 8 CICIDS2017 datasets'
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("SentinelNode: Production-Grade Security Detection System")
    print("=" * 70)
    print(f"Mode: {args.mode.upper()}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    logger.info("SentinelNode starting...")
    
    # Initialize database connection
    db_connector = None
    try:
        db_connector = create_db_connector_from_env()
        if db_connector:
            logger.info("✓ Database connection established")
        else:
            logger.warning("⚠ Database not configured, continuing without persistence")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        logger.warning("Continuing without database persistence")
    
    # Initialize alert manager
    alert_manager = AlertManager(
        csv_output_path='data/processed/alerts.csv',
        db_connector=db_connector
    )
    
    try:
        if args.mode == 'parquet' or args.process_all:
            # Process all CICIDS2017 datasets
            data_dir = args.data_dir
            
            if not os.path.exists(data_dir):
                logger.error(f"Data directory not found: {data_dir}")
                print(f"\n❌ Error: Data directory not found at {data_dir}")
                print("Please ensure CICIDS2017 parquet files are in the correct location.")
                return
            
            # Initialize processor
            processor = CICIDS2017Processor(
                data_dir=data_dir,
                db_connector=db_connector,
                alert_manager=alert_manager,
                chunk_size=10000
            )
            
            # Process all datasets
            stats = processor.process_all()
            
            # Print final summary
            print("\n" + "=" * 70)
            print("FINAL SUMMARY")
            print("=" * 70)
            print(f"Total Flows Processed: {stats['total_flows_processed']:,}")
            print(f"Total Attacks Detected: {stats['total_attacks_detected']:,}")
            print(f"Total Processing Time: {stats.get('total_processing_time', 0):.2f}s")
            
            if stats.get('attacks_by_type'):
                print("\n📊 Attacks by Type:")
                for event_type, count in sorted(stats['attacks_by_type'].items(), 
                                               key=lambda x: x[1], reverse=True):
                    print(f"  • {event_type}: {count:,}")
            
            print("\n✓ Alerts saved to: data/processed/alerts.csv")
            if db_connector:
                print("✓ Alerts stored in database")
            
            print("\n💡 Tip: Run 'python dashboard/app.py' to view the dashboard")
            print("=" * 70)
            
        elif args.mode == 'single':
            if not args.input:
                logger.error("--input required for single mode")
                print("\n❌ Error: --input required for single mode")
                return
            
            if not os.path.exists(args.input):
                logger.error(f"Input file not found: {args.input}")
                print(f"\n❌ Error: Input file not found at {args.input}")
                return
            
            # Process single file
            logger.info(f"Processing single file: {args.input}")
            
            from src.detectors.ssh_detector import SSHBruteForceDetector
            from src.detectors.ddos_detector import DDoSDetector
            import pandas as pd
            
            df = pd.read_parquet(args.input, engine='pyarrow')
            logger.info(f"Loaded {len(df):,} flows from {args.input}")
            
            # Determine detector based on file name
            if 'bruteforce' in args.input.lower() or 'ssh' in args.input.lower():
                detector = SSHBruteForceDetector(db_connector=db_connector)
                logger.info("Using SSH Brute-Force Detector")
            elif 'ddos' in args.input.lower() or 'dos' in args.input.lower():
                detector = DDoSDetector(db_connector=db_connector)
                logger.info("Using DDoS Detector")
            else:
                logger.warning("Could not determine detector type, using SSH detector")
                detector = SSHBruteForceDetector(db_connector=db_connector)
            
            # Add synthetic fields
            from src.data_processor import CICIDS2017Processor
            processor = CICIDS2017Processor(
                data_dir=os.path.dirname(args.input),
                db_connector=db_connector,
                alert_manager=alert_manager
            )
            df = processor._add_synthetic_fields(df)
            
            # Detect attacks
            detections = detector.detect(df)
            
            # Handle detections
            for detection in detections:
                alert_manager.send_alert(
                    src_ip=detection['src_ip'],
                    event_type=detection.get('event_type', 'unknown'),
                    severity=detection['severity'],
                    confidence_score=detection['confidence_score'],
                    pattern_type=detection['pattern_type'],
                    detection_time=detection['detection_time'],
                    raw_metrics=detection.get('raw_metrics')
                )
            
            print(f"\n✓ Detected {len(detections)} attacks")
            print(f"✓ Alerts saved to: data/processed/alerts.csv")
            
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
        print("\n\n⚠ Processing interrupted by user")
    except Exception as e:
        logger.error(f"Error during processing: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
    finally:
        if db_connector:
            db_connector.close()
            logger.info("Database connection closed")


if __name__ == "__main__":
    main()
