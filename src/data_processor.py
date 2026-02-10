import os
import pandas as pd
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from src.detectors.ssh_detector import SSHBruteForceDetector
from src.detectors.ddos_detector import DDoSDetector
from src.baseline_learner import BaselineLearner
from src.alert_manager import AlertManager

logger = logging.getLogger(__name__)


class CICIDS2017Processor:
    """
    Orchestrates processing of all CICIDS2017 parquet files.
    
    Processing order:
        1. Benign-Monday (baseline learning)
        2. Bruteforce-Tuesday (SSH/FTP attacks)
        3. DoS-Wednesday (DoS variants)
        4. Infiltration-Thursday
        5. WebAttacks-Thursday
        6. DDoS-Friday
        7. Portscan-Friday
        8. Botnet-Friday
    """
    
    # Dataset file mapping
    DATASETS = {
        'benign': 'Benign-Monday-no-metadata.parquet',
        'bruteforce': 'Bruteforce-Tuesday-no-metadata.parquet',
        'dos': 'DoS-Wednesday-no-metadata.parquet',
        'infiltration': 'Infiltration-Thursday-no-metadata.parquet',
        'webattacks': 'WebAttacks-Thursday-no-metadata.parquet',
        'ddos': 'DDoS-Friday-no-metadata.parquet',
        'portscan': 'Portscan-Friday-no-metadata.parquet',
        'botnet': 'Botnet-Friday-no-metadata.parquet'
    }
    
    # Processing order
    PROCESSING_ORDER = [
        'benign', 'bruteforce', 'dos', 'infiltration',
        'webattacks', 'ddos', 'portscan', 'botnet'
    ]
    
    def __init__(
        self,
        data_dir: str,
        db_connector=None,
        alert_manager: Optional[AlertManager] = None,
        chunk_size: int = 10000
    ):
        """
        Initialize data processor.
        
        Args:
            data_dir: Directory containing parquet files
            db_connector: Database connector
            alert_manager: Alert manager instance
            chunk_size: Number of rows to process at once
        """
        self.data_dir = data_dir
        self.db_connector = db_connector
        self.alert_manager = alert_manager
        self.chunk_size = chunk_size
        
        # Initialize detectors
        self.ssh_detector = SSHBruteForceDetector(db_connector=db_connector)
        self.ddos_detector = DDoSDetector(db_connector=db_connector)
        self.baseline_learner = BaselineLearner(db_connector=db_connector)
        
        # Statistics
        self.stats = {
            'total_flows_processed': 0,
            'total_attacks_detected': 0,
            'attacks_by_type': {},
            'processing_time': {}
        }
        
        logger.info("CICIDS2017 Processor initialized")
    
    def process_all(self) -> Dict[str, Any]:
        """
        Process all datasets in order.
        
        Returns:
            Dictionary with processing statistics
        """
        logger.info("=" * 70)
        logger.info("Starting CICIDS2017 Dataset Processing")
        logger.info("=" * 70)
        
        start_time = datetime.now()
        
        for dataset_name in self.PROCESSING_ORDER:
            file_name = self.DATASETS[dataset_name]
            file_path = os.path.join(self.data_dir, file_name)
            
            if not os.path.exists(file_path):
                logger.warning(f"Dataset not found: {file_path}, skipping")
                continue
            
            logger.info(f"\n{'=' * 70}")
            logger.info(f"Processing: {dataset_name.upper()} ({file_name})")
            logger.info(f"{'=' * 70}")
            
            dataset_start = datetime.now()
            
            if dataset_name == 'benign':
                self._process_benign(file_path)
            elif dataset_name == 'bruteforce':
                self._process_bruteforce(file_path)
            elif dataset_name in ['ddos', 'dos']:
                self._process_ddos(file_path, dataset_name)
            else:
                self._process_generic(file_path, dataset_name)
            
            dataset_time = (datetime.now() - dataset_start).total_seconds()
            self.stats['processing_time'][dataset_name] = dataset_time
            
            logger.info(f"Completed {dataset_name} in {dataset_time:.2f}s")
        
        total_time = (datetime.now() - start_time).total_seconds()
        self.stats['total_processing_time'] = total_time
        
        self._print_summary()
        
        return self.stats
    
    def _process_benign(self, file_path: str):
        """Process benign dataset for baseline learning."""
        logger.info("Learning behavioral baselines from benign traffic...")
        
        baseline_stats = self.baseline_learner.learn_from_parquet(file_path)
        
        # Set baseline stats for DDoS detector
        self.ddos_detector.set_baseline_stats(baseline_stats)
        
        # Update statistics
        self.stats['baseline_stats'] = baseline_stats
        
        logger.info(f"✓ Baseline learning complete: {baseline_stats.get('unique_ips', 0)} IPs profiled")
    
    def _process_bruteforce(self, file_path: str):
        """Process brute-force dataset (SSH-Patator, FTP-Patator)."""
        logger.info("Detecting SSH/FTP brute-force attacks...")
        
        df = pd.read_parquet(file_path, engine='pyarrow')
        
        # Add synthetic timestamp and src_ip
        df = self._add_synthetic_fields(df)
        
        # Filter for SSH-related traffic (we'll process all and let detector decide)
        # In CICIDS2017, SSH-Patator is labeled
        ssh_attacks = df[df['Label'].str.contains('SSH', case=False, na=False)]
        
        if not ssh_attacks.empty:
            logger.info(f"Processing {len(ssh_attacks):,} SSH-related flows")
            detections = self.ssh_detector.detect(ssh_attacks)
            self._handle_detections(detections, 'ssh_bruteforce')
        
        # Also check FTP
        ftp_attacks = df[df['Label'].str.contains('FTP', case=False, na=False)]
        if not ftp_attacks.empty:
            logger.info(f"Processing {len(ftp_attacks):,} FTP-related flows")
            # FTP uses similar detection logic
            detections = self.ssh_detector.detect(ftp_attacks)
            self._handle_detections(detections, 'ftp_bruteforce')
        
        self.stats['total_flows_processed'] += len(df)
    
    def _process_ddos(self, file_path: str, dataset_name: str):
        """Process DDoS/DoS datasets."""
        logger.info(f"Detecting {dataset_name.upper()} attacks...")
        
        df = pd.read_parquet(file_path, engine='pyarrow')
        
        # Add synthetic fields
        df = self._add_synthetic_fields(df)
        
        # Filter for attack traffic
        attack_df = df[df['Label'] != 'Benign']
        
        if not attack_df.empty:
            logger.info(f"Processing {len(attack_df):,} attack flows")
            
            # Process in chunks to manage memory
            for i in range(0, len(attack_df), self.chunk_size):
                chunk = attack_df.iloc[i:i+self.chunk_size]
                detections = self.ddos_detector.detect(chunk)
                self._handle_detections(detections, dataset_name)
                
                if (i + self.chunk_size) % 50000 == 0:
                    logger.info(f"  Processed {i + self.chunk_size:,} flows...")
        
        self.stats['total_flows_processed'] += len(df)
    
    def _process_generic(self, file_path: str, dataset_name: str):
        """Process other datasets (portscan, botnet, etc.)."""
        logger.info(f"Processing {dataset_name} dataset...")
        
        df = pd.read_parquet(file_path, engine='pyarrow')
        
        # Add synthetic fields
        df = self._add_synthetic_fields(df)
        
        # Filter for attack traffic
        attack_df = df[df['Label'] != 'Benign']
        
        if not attack_df.empty:
            logger.info(f"Found {len(attack_df):,} attack flows (logged but not actively detected)")
            
            # For now, just log these attacks
            # Future: implement specific detectors for portscan, botnet, etc.
            for _, row in attack_df.head(10).iterrows():  # Sample first 10
                logger.info(f"  {row['Label']}: Protocol={row['Protocol']}, "
                          f"Duration={row['Flow Duration']}, "
                          f"Packets={row['Total Fwd Packets'] + row['Total Backward Packets']}")
        
        self.stats['total_flows_processed'] += len(df)
    
    def _add_synthetic_fields(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add synthetic timestamp and src_ip fields.
        
        CICIDS2017 parquet files don't have these, so we generate them.
        In production, extract from actual packet captures.
        """
        import numpy as np
        
        # Add timestamp (sequential, starting from now)
        base_time = datetime.now()
        df['timestamp'] = pd.date_range(start=base_time, periods=len(df), freq='100ms')
        
        # Add source IP (synthetic based on flow hash)
        np.random.seed(42)
        ip_ids = []
        for idx, row in df.iterrows():
            flow_hash = hash(str(row.get('Flow Duration', 0)) + 
                           str(row.get('Total Fwd Packets', 0)) +
                           str(idx))
            octet3 = abs(flow_hash) % 256
            octet4 = abs(flow_hash // 256) % 256
            ip = f"192.168.{octet3}.{octet4}"
            ip_ids.append(ip)
        
        df['src_ip'] = ip_ids
        
        return df
    
    def _handle_detections(self, detections: List[Dict[str, Any]], event_type_prefix: str):
        """
        Handle detected attacks by sending alerts.
        
        Args:
            detections: List of detection dictionaries
            event_type_prefix: Prefix for event type
        """
        for detection in detections:
            # Send alert through alert manager
            if self.alert_manager:
                self.alert_manager.send_alert(
                    src_ip=detection['src_ip'],
                    event_type=detection.get('event_type', event_type_prefix),
                    severity=detection['severity'],
                    confidence_score=detection['confidence_score'],
                    pattern_type=detection['pattern_type'],
                    detection_time=detection['detection_time'],
                    raw_metrics=detection.get('raw_metrics'),
                    **{k: v for k, v in detection.items() 
                       if k not in ['src_ip', 'event_type', 'severity', 'confidence_score', 
                                   'pattern_type', 'detection_time', 'raw_metrics']}
                )
            
            # Update statistics
            self.stats['total_attacks_detected'] += 1
            event_type = detection.get('event_type', event_type_prefix)
            self.stats['attacks_by_type'][event_type] = \
                self.stats['attacks_by_type'].get(event_type, 0) + 1
    
    def _print_summary(self):
        """Print processing summary."""
        logger.info("\n" + "=" * 70)
        logger.info("PROCESSING SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Total Flows Processed: {self.stats['total_flows_processed']:,}")
        logger.info(f"Total Attacks Detected: {self.stats['total_attacks_detected']:,}")
        logger.info(f"Total Processing Time: {self.stats['total_processing_time']:.2f}s")
        
        if self.stats['attacks_by_type']:
            logger.info("\nAttacks by Type:")
            for event_type, count in sorted(self.stats['attacks_by_type'].items()):
                logger.info(f"  {event_type}: {count:,}")
        
        if self.stats['processing_time']:
            logger.info("\nProcessing Time by Dataset:")
            for dataset, time_sec in self.stats['processing_time'].items():
                logger.info(f"  {dataset}: {time_sec:.2f}s")
        
        logger.info("=" * 70)
