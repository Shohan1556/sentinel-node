import pandas as pd
import numpy as np
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class DDoSDetector:
    """
    Production-grade DDoS detector with multi-vector analysis.
    
    Layers:
        1. Volumetric: PPS baseline comparison, connection rate monitoring
        2. Protocol: SYN flood, UDP flood detection
        3. Behavioral: Traffic asymmetry, entropy analysis
    """
    
    # Volumetric thresholds
    SIGMA_MULTIPLIER = 3.0  # 3-sigma for anomaly detection
    HIGH_CONNECTION_RATE = 1000  # flows per second
    
    # Protocol detection thresholds
    SYN_FLOOD_DURATION_MS = 100  # Short duration for SYN flood
    SYN_FLOOD_ASYMMETRY = 5  # Fwd >> Bwd packets ratio
    UDP_FLOOD_PPS_THRESHOLD = 500  # High packet rate for UDP
    
    # Behavioral thresholds
    TRAFFIC_ASYMMETRY_RATIO = 10  # Inbound >> Outbound
    LOW_ENTROPY_THRESHOLD = 0.3  # Repetitive patterns
    
    # Legitimate service ports to exclude from UDP flood detection
    LEGITIMATE_UDP_PORTS = {53, 123, 161, 162, 514}  # DNS, NTP, SNMP, Syslog
    
    def __init__(self, db_connector=None, baseline_stats: Optional[Dict] = None):
        """
        Initialize DDoS detector.
        
        Args:
            db_connector: Optional database connector for baseline queries
            baseline_stats: Optional pre-computed baseline statistics
        """
        self.db_connector = db_connector
        self.baseline_stats = baseline_stats or {}
        
        # Tracking structures
        self.ip_flow_counts = defaultdict(int)
        self.ip_timestamps = defaultdict(list)
        
        logger.info("DDoS Detector initialized with multi-vector analysis")
    
    def detect(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Analyze DataFrame for DDoS patterns across all vectors.
        
        Args:
            df: DataFrame with CICIDS2017 flow features:
                - 'src_ip': Source IP address
                - 'Protocol': Protocol number (6=TCP, 17=UDP)
                - 'Flow Duration': Duration in microseconds
                - 'Total Fwd Packets': Forward packet count
                - 'Total Backward Packets': Backward packet count
                - 'SYN Flag Count': SYN flags
                - 'Flow Packets/s': Packets per second
                - Additional flow features
                
        Returns:
            List of detected DDoS attacks with severity and evidence
        """
        if df.empty:
            return []
        
        attacks = []
        
        try:
            # Ensure required columns exist
            required_cols = ['src_ip', 'Protocol', 'Flow Duration', 
                           'Total Fwd Packets', 'Total Backward Packets']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                logger.error(f"Missing required columns: {missing_cols}")
                return []
            
            # Process each flow
            for idx, row in df.iterrows():
                src_ip = str(row['src_ip'])
                
                # Layer 1: Volumetric Detection
                volumetric_detections = self._detect_volumetric(src_ip, row)
                attacks.extend(volumetric_detections)
                
                # Layer 2: Protocol Detection
                protocol_detections = self._detect_protocol(src_ip, row)
                attacks.extend(protocol_detections)
                
                # Layer 3: Behavioral Detection
                behavioral_detections = self._detect_behavioral(src_ip, row)
                attacks.extend(behavioral_detections)
            
            # Deduplicate attacks
            attacks = self._deduplicate_attacks(attacks)
            
            logger.info(f"DDoS Detection complete: {len(attacks)} attacks detected")
            return attacks
            
        except Exception as e:
            logger.error(f"Error during DDoS detection: {e}", exc_info=True)
            return []
    
    def _detect_volumetric(self, src_ip: str, flow_data: pd.Series) -> List[Dict[str, Any]]:
        """
        Layer 1: Volumetric detection (PPS anomaly & connection rate).
        
        Returns:
            List of volumetric detections
        """
        detections = []
        
        # Calculate PPS for this flow
        flow_duration_sec = flow_data['Flow Duration'] / 1_000_000  # Convert μs to seconds
        if flow_duration_sec > 0:
            pps = (flow_data['Total Fwd Packets'] + flow_data['Total Backward Packets']) / flow_duration_sec
        else:
            pps = 0
        
        # Get baseline PPS for this IP
        baseline = None
        if self.db_connector:
            baseline = self.db_connector.get_ip_baseline(src_ip)
        
        # 3-sigma anomaly detection
        if baseline and baseline.get('baseline_pps'):
            baseline_pps = baseline['baseline_pps']
            # Use global std if available, otherwise estimate
            std_pps = self.baseline_stats.get('global_pps_std', baseline_pps * 0.5)
            threshold = baseline_pps + (self.SIGMA_MULTIPLIER * std_pps)
            
            if pps > threshold:
                detections.append({
                    'src_ip': src_ip,
                    'detection_time': datetime.now(),
                    'event_type': 'ddos_volumetric',
                    'severity': 'high',
                    'confidence_score': min(0.85 + (pps - threshold) / threshold * 0.1, 0.98),
                    'pattern_type': 'pps_anomaly',
                    'pps': pps,
                    'baseline_pps': baseline_pps,
                    'threshold': threshold,
                    'raw_metrics': flow_data.to_dict()
                })
        
        # High connection rate detection (use Flow Packets/s if available)
        flow_pps = flow_data.get('Flow Packets/s', pps)
        if flow_pps > self.HIGH_CONNECTION_RATE:
            detections.append({
                'src_ip': src_ip,
                'detection_time': datetime.now(),
                'event_type': 'ddos_volumetric',
                'severity': 'critical',
                'confidence_score': min(0.90 + (flow_pps - self.HIGH_CONNECTION_RATE) / 10000 * 0.05, 0.99),
                'pattern_type': 'high_connection_rate',
                'flow_pps': flow_pps,
                'threshold': self.HIGH_CONNECTION_RATE,
                'raw_metrics': flow_data.to_dict()
            })
        
        return detections
    
    def _detect_protocol(self, src_ip: str, flow_data: pd.Series) -> List[Dict[str, Any]]:
        """
        Layer 2: Protocol-specific detection (SYN flood, UDP flood).
        
        Returns:
            List of protocol-based detections
        """
        detections = []
        protocol = flow_data['Protocol']
        
        # SYN Flood Detection (TCP protocol = 6)
        if protocol == 6:
            fwd_packets = flow_data['Total Fwd Packets']
            bwd_packets = flow_data['Total Backward Packets']
            flow_duration_ms = flow_data['Flow Duration'] / 1000  # Convert to ms
            syn_count = flow_data.get('SYN Flag Count', 0)
            
            # Characteristics: High fwd, low bwd, short duration, SYN flags
            if (fwd_packets > bwd_packets * self.SYN_FLOOD_ASYMMETRY and
                flow_duration_ms < self.SYN_FLOOD_DURATION_MS and
                syn_count > 0):
                
                detections.append({
                    'src_ip': src_ip,
                    'detection_time': datetime.now(),
                    'event_type': 'ddos_syn',
                    'severity': 'high',
                    'confidence_score': min(0.88 + (fwd_packets / max(bwd_packets, 1)) * 0.01, 0.97),
                    'pattern_type': 'syn_flood',
                    'fwd_packets': int(fwd_packets),
                    'bwd_packets': int(bwd_packets),
                    'asymmetry_ratio': fwd_packets / max(bwd_packets, 1),
                    'flow_duration_ms': flow_duration_ms,
                    'syn_count': int(syn_count),
                    'raw_metrics': flow_data.to_dict()
                })
        
        # UDP Flood Detection (UDP protocol = 17)
        elif protocol == 17:
            dst_port = flow_data.get('Destination Port', 0)
            flow_pps = flow_data.get('Flow Packets/s', 0)
            
            # Exclude legitimate UDP services
            if dst_port not in self.LEGITIMATE_UDP_PORTS and flow_pps > self.UDP_FLOOD_PPS_THRESHOLD:
                detections.append({
                    'src_ip': src_ip,
                    'detection_time': datetime.now(),
                    'event_type': 'ddos_udp',
                    'severity': 'high',
                    'confidence_score': min(0.85 + flow_pps / 10000 * 0.1, 0.96),
                    'pattern_type': 'udp_flood',
                    'flow_pps': flow_pps,
                    'dst_port': int(dst_port),
                    'threshold': self.UDP_FLOOD_PPS_THRESHOLD,
                    'raw_metrics': flow_data.to_dict()
                })
        
        return detections
    
    def _detect_behavioral(self, src_ip: str, flow_data: pd.Series) -> List[Dict[str, Any]]:
        """
        Layer 3: Behavioral detection (traffic asymmetry, entropy).
        
        Returns:
            List of behavioral detections
        """
        detections = []
        
        fwd_packets = flow_data['Total Fwd Packets']
        bwd_packets = flow_data['Total Backward Packets']
        
        # Traffic Asymmetry Detection
        if bwd_packets > 0:
            asymmetry_ratio = fwd_packets / bwd_packets
            
            if asymmetry_ratio > self.TRAFFIC_ASYMMETRY_RATIO:
                detections.append({
                    'src_ip': src_ip,
                    'detection_time': datetime.now(),
                    'event_type': 'ddos_behavioral',
                    'severity': 'medium',
                    'confidence_score': min(0.75 + asymmetry_ratio / 100 * 0.15, 0.92),
                    'pattern_type': 'traffic_asymmetry',
                    'asymmetry_ratio': asymmetry_ratio,
                    'fwd_packets': int(fwd_packets),
                    'bwd_packets': int(bwd_packets),
                    'raw_metrics': flow_data.to_dict()
                })
        
        # Low Entropy Detection (repetitive patterns)
        entropy = self._calculate_flow_entropy(flow_data)
        if entropy < self.LOW_ENTROPY_THRESHOLD:
            detections.append({
                'src_ip': src_ip,
                'detection_time': datetime.now(),
                'event_type': 'ddos_behavioral',
                'severity': 'medium',
                'confidence_score': 0.70 + (self.LOW_ENTROPY_THRESHOLD - entropy) * 0.5,
                'pattern_type': 'low_entropy',
                'entropy': entropy,
                'threshold': self.LOW_ENTROPY_THRESHOLD,
                'raw_metrics': flow_data.to_dict()
            })
        
        return detections
    
    def _calculate_flow_entropy(self, flow_data: pd.Series) -> float:
        """
        Calculate entropy of flow characteristics.
        
        Low entropy indicates repetitive patterns (DDoS characteristic).
        
        Returns:
            Entropy value (0.0 = very repetitive, 1.0 = random)
        """
        try:
            # Use packet size and IAT features for entropy calculation
            features = [
                flow_data.get('Fwd Packet Length Mean', 0),
                flow_data.get('Bwd Packet Length Mean', 0),
                flow_data.get('Flow IAT Mean', 0),
                flow_data.get('Packet Length Std', 0),
            ]
            
            # Normalize and calculate Shannon entropy
            features = np.array([f for f in features if f > 0])
            if len(features) == 0:
                return 0.0
            
            # Normalize to probabilities
            total = np.sum(features)
            if total == 0:
                return 0.0
            
            probs = features / total
            entropy = -np.sum(probs * np.log2(probs + 1e-10))
            
            # Normalize to 0-1 range (max entropy for 4 features is log2(4) = 2)
            normalized_entropy = entropy / 2.0
            
            return min(max(normalized_entropy, 0.0), 1.0)
            
        except Exception as e:
            logger.debug(f"Error calculating entropy: {e}")
            return 0.5  # Default to medium entropy
    
    def _deduplicate_attacks(self, attacks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate detections (same IP, same pattern type).
        
        Args:
            attacks: List of detected attacks
            
        Returns:
            Deduplicated list
        """
        if not attacks:
            return []
        
        # Keep highest confidence detection per (IP, pattern_type)
        seen = {}  # (ip, pattern_type) -> attack
        
        for attack in attacks:
            key = (attack['src_ip'], attack['pattern_type'])
            existing = seen.get(key)
            
            if not existing or attack['confidence_score'] > existing['confidence_score']:
                seen[key] = attack
        
        return list(seen.values())
    
    def set_baseline_stats(self, stats: Dict[str, Any]):
        """
        Set global baseline statistics for anomaly detection.
        
        Args:
            stats: Dictionary with keys like 'global_pps_mean', 'global_pps_std'
        """
        self.baseline_stats = stats
        logger.info(f"Baseline statistics updated: {stats}")
    
    def reset(self):
        """Reset tracking structures (useful for testing)."""
        self.ip_flow_counts.clear()
        self.ip_timestamps.clear()
        logger.info("DDoS detector state reset")


# Import datetime for timestamps
from datetime import datetime
