import pandas as pd
import numpy as np
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class BaselineLearner:
    
    
    def __init__(self, db_connector=None):
        """
        Initialize baseline learner.
        
        Args:
            db_connector: Database connector for storing baselines
        """
        self.db_connector = db_connector
        self.baseline_stats = {}
        self.ip_baselines = {}
        
        logger.info("Baseline Learner initialized")
    
    def learn_from_parquet(self, parquet_path: str) -> Dict[str, Any]:
        """
        Learn baselines from benign parquet file.
        
        Args:
            parquet_path: Path to Benign-Monday.parquet
            
        Returns:
            Dictionary with global baseline statistics
        """
        try:
            logger.info(f"Loading benign data from {parquet_path}")
            df = pd.read_parquet(parquet_path, engine='pyarrow')
            
            # Filter for benign traffic only
            if 'Label' in df.columns:
                df = df[df['Label'] == 'Benign'].copy()
            
            logger.info(f"Processing {len(df):,} benign flows for baseline learning")
            
            # Add source IP if not present (extract from flow ID or use placeholder)
            if 'src_ip' not in df.columns:
                df['src_ip'] = self._extract_source_ips(df)
            
            # Calculate PPS for each flow
            df['pps'] = self._calculate_pps(df)
            
            # Compute per-IP baselines
            self._compute_ip_baselines(df)
            
            # Compute global statistics
            self._compute_global_stats(df)
            
            # Store baselines in database
            if self.db_connector:
                self._store_baselines()
            
            logger.info(f"Baseline learning complete: {len(self.ip_baselines)} IPs profiled")
            return self.baseline_stats
            
        except Exception as e:
            logger.error(f"Error learning baselines: {e}", exc_info=True)
            return {}
    
    def _extract_source_ips(self, df: pd.DataFrame) -> pd.Series:
        """
        Extract source IPs from flow data.
        
        CICIDS2017 parquet files don't have explicit IP columns,
        so we generate synthetic IPs based on flow characteristics.
        
        In production, parse from actual network captures.
        """
        # Generate synthetic IPs based on flow hash
        # In production, extract from actual packet captures
        np.random.seed(42)  # For reproducibility
        
        # Create IP-like identifiers from flow features
        ip_ids = []
        for idx, row in df.iterrows():
            # Use flow characteristics to generate consistent IP
            flow_hash = hash(str(row.get('Flow Duration', 0)) + 
                           str(row.get('Total Fwd Packets', 0)) +
                           str(idx))
            
            # Generate IP in format 192.168.x.y
            octet3 = abs(flow_hash) % 256
            octet4 = abs(flow_hash // 256) % 256
            ip = f"192.168.{octet3}.{octet4}"
            ip_ids.append(ip)
        
        return pd.Series(ip_ids, index=df.index)
    
    def _calculate_pps(self, df: pd.DataFrame) -> pd.Series:
        """
        Calculate packets per second for each flow.
        
        Args:
            df: DataFrame with flow data
            
        Returns:
            Series with PPS values
        """
        # Flow Duration is in microseconds
        duration_sec = df['Flow Duration'] / 1_000_000
        total_packets = df['Total Fwd Packets'] + df['Total Backward Packets']
        
        # Avoid division by zero
        pps = np.where(duration_sec > 0, total_packets / duration_sec, 0)
        
        return pd.Series(pps, index=df.index)
    
    def _compute_ip_baselines(self, df: pd.DataFrame):
        """
        Compute baseline PPS for each source IP.
        
        Args:
            df: DataFrame with 'src_ip' and 'pps' columns
        """
        # Group by source IP and compute statistics
        ip_groups = df.groupby('src_ip')['pps'].agg(['mean', 'std', 'count', 'min', 'max'])
        
        for ip, stats in ip_groups.iterrows():
            self.ip_baselines[ip] = {
                'ip_address': ip,
                'baseline_pps': float(stats['mean']),
                'pps_std': float(stats['std']) if not pd.isna(stats['std']) else 0.0,
                'flow_count': int(stats['count']),
                'min_pps': float(stats['min']),
                'max_pps': float(stats['max']),
                'reputation_score': 50,  # Neutral baseline
                'first_seen': datetime.now(),
                'last_seen': datetime.now()
            }
        
        logger.info(f"Computed baselines for {len(self.ip_baselines)} unique IPs")
    
    def _compute_global_stats(self, df: pd.DataFrame):
        """
        Compute global traffic statistics.
        
        Args:
            df: DataFrame with flow data
        """
        self.baseline_stats = {
            'global_pps_mean': float(df['pps'].mean()),
            'global_pps_std': float(df['pps'].std()),
            'global_pps_median': float(df['pps'].median()),
            'global_pps_95th': float(df['pps'].quantile(0.95)),
            'total_flows': len(df),
            'unique_ips': df['src_ip'].nunique(),
            'avg_flow_duration': float(df['Flow Duration'].mean()),
            'avg_packets_per_flow': float((df['Total Fwd Packets'] + df['Total Backward Packets']).mean()),
            'learned_at': datetime.now().isoformat()
        }
        
        logger.info(f"Global baseline stats: PPS mean={self.baseline_stats['global_pps_mean']:.2f}, "
                   f"std={self.baseline_stats['global_pps_std']:.2f}")
    
    def _store_baselines(self):
        """Store learned baselines in database."""
        if not self.db_connector:
            logger.warning("No database connector available, skipping baseline storage")
            return
        
        stored_count = 0
        for ip, baseline in self.ip_baselines.items():
            success = self.db_connector.upsert_ip_profile(
                ip_address=baseline['ip_address'],
                first_seen=baseline['first_seen'],
                last_seen=baseline['last_seen'],
                baseline_pps=baseline['baseline_pps'],
                reputation_score=baseline['reputation_score']
            )
            if success:
                stored_count += 1
        
        logger.info(f"Stored {stored_count}/{len(self.ip_baselines)} IP baselines in database")
    
    def get_baseline_stats(self) -> Dict[str, Any]:
        """
        Get global baseline statistics.
        
        Returns:
            Dictionary with global stats
        """
        return self.baseline_stats
    
    def get_ip_baseline(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get baseline for specific IP.
        
        Args:
            ip_address: IP to query
            
        Returns:
            Baseline dictionary or None
        """
        return self.ip_baselines.get(ip_address)
    
    def export_baselines(self, output_path: str):
        """
        Export baselines to JSON file.
        
        Args:
            output_path: Path to save JSON file
        """
        import json
        
        export_data = {
            'global_stats': self.baseline_stats,
            'ip_baselines': {
                ip: {k: v.isoformat() if isinstance(v, datetime) else v 
                     for k, v in baseline.items()}
                for ip, baseline in self.ip_baselines.items()
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Baselines exported to {output_path}")
