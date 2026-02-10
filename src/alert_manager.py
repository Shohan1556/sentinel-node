"""
Alert management module for SentinelNode.

Handles alert distribution to multiple outputs: console, CSV, and database.
"""

import csv
import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertManager:
    """
    Manages security alerts with multi-channel output support.
    
    Supports console output, CSV logging, and optional database persistence.
    """
    
    def __init__(
        self,
        csv_output_path: Optional[str] = None,
        db_connector: Optional[Any] = None
    ):
        """
        Initialize AlertManager with optional CSV and database outputs.
        
        Args:
            csv_output_path: Path to CSV file for alert logging
            db_connector: DatabaseConnector instance for database persistence
        """
        self.csv_output_path = csv_output_path
        self.db_connector = db_connector
        
        # Initialize CSV file with headers if path is provided
        if self.csv_output_path:
            self._initialize_csv()
        
        # Log configuration
        logger.info(f"AlertManager initialized:")
        logger.info(f"  - Console output: Enabled")
        logger.info(f"  - CSV output: {'Enabled' if csv_output_path else 'Disabled'}")
        logger.info(f"  - Database output: {'Enabled' if db_connector else 'Disabled'}")
    
    def _initialize_csv(self) -> None:
        """
        Create CSV file with headers if it doesn't exist.
        """
        try:
            # Create directory if it doesn't exist
            csv_dir = os.path.dirname(self.csv_output_path)
            if csv_dir:
                Path(csv_dir).mkdir(parents=True, exist_ok=True)
            
            # Check if file exists and has content
            file_exists = os.path.exists(self.csv_output_path)
            file_has_content = file_exists and os.path.getsize(self.csv_output_path) > 0
            
            if not file_has_content:
                with open(self.csv_output_path, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        'timestamp',
                        'source_ip',
                        'event_type',
                        'dataset_source'
                    ])
                logger.info(f"CSV file initialized: {self.csv_output_path}")
        except Exception as e:
            logger.error(f"Error initializing CSV file: {e}")
    
    def send_alert(
        self,
        message: str,
        timestamp: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        event_type: str = "SSH-BruteForce",
        dataset_source: str = "CICIDS2017"
    ) -> None:
        """
        Send alert to all configured outputs.
        
        Args:
            message: Human-readable alert message
            timestamp: When the event occurred (detection_time)
            source_ip: IP address of the attacker
            event_type: Type of security event
            dataset_source: Source of the dataset
        """
        # Default timestamp to now if not provided
        if timestamp is None:
            timestamp = datetime.now()
        
        # 1. Console output (always enabled)
        print(f"{message}")
        
        # 2. CSV output (if configured)
        if self.csv_output_path and source_ip:
            self.log_to_csv(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=event_type,
                dataset_source=dataset_source
            )
        
        # 3. Database output (if configured)
        if self.db_connector and source_ip:
            self.log_to_database(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=event_type,
                dataset_source=dataset_source
            )
    
    def log_to_csv(
        self,
        timestamp: datetime,
        source_ip: str,
        event_type: str,
        dataset_source: str = "CICIDS2017"
    ) -> bool:
        """
        Log alert to CSV file.
        
        Args:
            timestamp: When the event occurred
            source_ip: IP address of the attacker
            event_type: Type of security event
            dataset_source: Source of the dataset
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(self.csv_output_path, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([
                    timestamp.isoformat(),
                    source_ip,
                    event_type,
                    dataset_source
                ])
            logger.debug(f"Alert logged to CSV: {source_ip}")
            return True
        except Exception as e:
            logger.error(f"Error writing to CSV: {e}")
            return False
    
    def log_to_database(
        self,
        timestamp: datetime,
        source_ip: str,
        event_type: str,
        dataset_source: str = "CICIDS2017"
    ) -> Optional[int]:
        """
        Log alert to database.
        
        Args:
            timestamp: When the event occurred
            source_ip: IP address of the attacker
            event_type: Type of security event
            dataset_source: Source of the dataset
            
        Returns:
            int: Alert ID if successful, None otherwise
        """
        try:
            alert_id = self.db_connector.insert_alert(
                detection_time=timestamp,
                source_ip=source_ip,
                event_type=event_type,
                dataset_source=dataset_source
            )
            
            if alert_id:
                logger.debug(f"Alert logged to database with ID: {alert_id}")
            return alert_id
            
        except Exception as e:
            logger.error(f"Error writing to database: {e}")
            return None
