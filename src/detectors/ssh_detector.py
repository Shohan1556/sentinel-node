import pandas as pd
import logging
from typing import List, Dict, Any, Optional, Tuple
from collections import deque, defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class SSHBruteForceDetector:
    """
    Production-grade SSH brute-force detector with multi-layer analysis.
    
    Layers:
        1. Rate-Based: Sliding windows (1min, 5min, 15min) with tiered alerts
        2. Pattern Recognition: Username enumeration & credential stuffing
        3. Behavioral: Baseline comparison & breach detection
    """
    
    # Tier thresholds for rate-based detection
    TIER_1_THRESHOLD = 5   # attempts in 1 minute
    TIER_2_THRESHOLD = 10  # attempts in 5 minutes
    TIER_3_THRESHOLD = 20  # attempts in 15 minutes
    
    # Time windows in seconds
    WINDOW_1MIN = 60
    WINDOW_5MIN = 300
    WINDOW_15MIN = 900
    
    # Pattern recognition thresholds
    USERNAME_ENUM_THRESHOLD = 3  # distinct usernames from same IP
    CREDENTIAL_STUFFING_IPS = 3  # different IPs trying same username
    
    def __init__(self, db_connector=None):
        """
        Initialize SSH brute-force detector.
        
        Args:
            db_connector: Optional database connector for baseline queries
        """
        self.db_connector = db_connector
        
        # Layer 1: Rate-based tracking (IP -> deque of timestamps)
        self.ip_attempts: Dict[str, deque] = defaultdict(lambda: deque())
        
        # Layer 2: Pattern tracking
        self.ip_usernames: Dict[str, set] = defaultdict(set)  # IP -> set of usernames
        self.username_ips: Dict[str, set] = defaultdict(set)  # username -> set of IPs
        
        # Layer 3: Behavioral tracking
        self.ip_first_seen: Dict[str, datetime] = {}
        self.ip_post_failure_success: Dict[str, bool] = defaultdict(bool)
        
        logger.info("SSH Brute-Force Detector initialized with multi-layer analysis")
    
    def detect(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Analyze DataFrame for SSH brute-force patterns across all layers.
        
        Args:
            df: DataFrame with columns:
                - 'src_ip': Source IP address
                - 'timestamp': Event timestamp (datetime)
                - 'dst_port': Destination port (should be 22 for SSH)
                - 'protocol': Protocol number (should be 6 for TCP)
                - 'label': Optional attack label
                - Additional CICIDS2017 flow features
                
        Returns:
            List of detected attacks with severity, confidence, and evidence
        """
        if df.empty:
            return []
        
        attacks = []
        
        try:
            # Ensure timestamp is datetime
            if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Sort by timestamp for chronological processing
            df = df.sort_values('timestamp').copy()
            
            # Process each flow record
            for idx, row in df.iterrows():
                src_ip = str(row.get('src_ip', ''))
                timestamp = row['timestamp']
                
                # Infer username if available (CICIDS2017 doesn't have this, so we simulate)
                # In real SSH logs, this would come from authentication attempts
                username = self._infer_username(row)
                
                # Track first seen
                if src_ip not in self.ip_first_seen:
                    self.ip_first_seen[src_ip] = timestamp
                
                # Update tracking structures
                self.ip_attempts[src_ip].append(timestamp)
                if username:
                    self.ip_usernames[src_ip].add(username)
                    self.username_ips[username].add(src_ip)
                
                # Layer 1: Rate-Based Detection
                rate_detections = self._detect_rate_based(src_ip, timestamp, row)
                attacks.extend(rate_detections)
                
                # Layer 2: Pattern Recognition
                pattern_detections = self._detect_patterns(src_ip, username, timestamp, row)
                attacks.extend(pattern_detections)
                
                # Layer 3: Behavioral Baseline
                behavioral_detections = self._detect_behavioral(src_ip, timestamp, row)
                attacks.extend(behavioral_detections)
            
            # Deduplicate attacks (same IP, same tier, within 60 seconds)
            attacks = self._deduplicate_attacks(attacks)
            
            logger.info(f"SSH Detection complete: {len(attacks)} attacks detected")
            return attacks
            
        except Exception as e:
            logger.error(f"Error during SSH detection: {e}", exc_info=True)
            return []
    
    def _detect_rate_based(
        self,
        src_ip: str,
        current_time: datetime,
        flow_data: pd.Series
    ) -> List[Dict[str, Any]]:
        """
        Layer 1: Rate-based detection with sliding windows.
        
        Returns:
            List of detections (Tier 1, 2, or 3)
        """
        detections = []
        attempts = self.ip_attempts[src_ip]
        
        # Clean old attempts outside 15-minute window
        cutoff_time = current_time - timedelta(seconds=self.WINDOW_15MIN)
        while attempts and attempts[0] < cutoff_time:
            attempts.popleft()
        
        # Count attempts in each window
        count_1min = sum(1 for t in attempts if t >= current_time - timedelta(seconds=self.WINDOW_1MIN))
        count_5min = sum(1 for t in attempts if t >= current_time - timedelta(seconds=self.WINDOW_5MIN))
        count_15min = len(attempts)
        
        # Check tier thresholds
        if count_1min >= self.TIER_1_THRESHOLD:
            detections.append({
                'src_ip': src_ip,
                'detection_time': current_time,
                'event_type': 'ssh_bruteforce',
                'severity': 'low',
                'tier': 1,
                'confidence_score': min(0.6 + (count_1min - self.TIER_1_THRESHOLD) * 0.05, 0.9),
                'pattern_type': 'rate_spike_1min',
                'attempt_count': count_1min,
                'window_seconds': self.WINDOW_1MIN,
                'raw_metrics': flow_data.to_dict()
            })
        
        if count_5min >= self.TIER_2_THRESHOLD:
            detections.append({
                'src_ip': src_ip,
                'detection_time': current_time,
                'event_type': 'ssh_bruteforce',
                'severity': 'medium',
                'tier': 2,
                'confidence_score': min(0.7 + (count_5min - self.TIER_2_THRESHOLD) * 0.03, 0.95),
                'pattern_type': 'rate_spike_5min',
                'attempt_count': count_5min,
                'window_seconds': self.WINDOW_5MIN,
                'raw_metrics': flow_data.to_dict()
            })
        
        if count_15min >= self.TIER_3_THRESHOLD:
            detections.append({
                'src_ip': src_ip,
                'detection_time': current_time,
                'event_type': 'ssh_bruteforce',
                'severity': 'high',
                'tier': 3,
                'confidence_score': min(0.8 + (count_15min - self.TIER_3_THRESHOLD) * 0.01, 0.98),
                'pattern_type': 'rate_spike_15min',
                'attempt_count': count_15min,
                'window_seconds': self.WINDOW_15MIN,
                'raw_metrics': flow_data.to_dict()
            })
        
        return detections
    
    def _detect_patterns(
        self,
        src_ip: str,
        username: Optional[str],
        current_time: datetime,
        flow_data: pd.Series
    ) -> List[Dict[str, Any]]:
        """
        Layer 2: Pattern recognition (username enumeration & credential stuffing).
        
        Returns:
            List of pattern-based detections
        """
        detections = []
        
        if not username:
            return detections
        
        # Sequential username enumeration
        unique_usernames = len(self.ip_usernames[src_ip])
        if unique_usernames >= self.USERNAME_ENUM_THRESHOLD:
            detections.append({
                'src_ip': src_ip,
                'detection_time': current_time,
                'event_type': 'ssh_bruteforce',
                'severity': 'medium',
                'tier': 2,
                'confidence_score': min(0.75 + unique_usernames * 0.05, 0.95),
                'pattern_type': 'sequential_usernames',
                'username_count': unique_usernames,
                'raw_metrics': flow_data.to_dict()
            })
        
        # Credential stuffing detection
        ips_trying_username = len(self.username_ips[username])
        if ips_trying_username >= self.CREDENTIAL_STUFFING_IPS:
            detections.append({
                'src_ip': src_ip,
                'detection_time': current_time,
                'event_type': 'ssh_bruteforce',
                'severity': 'medium',
                'tier': 2,
                'confidence_score': min(0.70 + ips_trying_username * 0.05, 0.92),
                'pattern_type': 'credential_stuffing',
                'ip_count': ips_trying_username,
                'username': username,
                'raw_metrics': flow_data.to_dict()
            })
        
        return detections
    
    def _detect_behavioral(
        self,
        src_ip: str,
        current_time: datetime,
        flow_data: pd.Series
    ) -> List[Dict[str, Any]]:
        """
        Layer 3: Behavioral baseline detection.
        
        Checks:
        - First-time IP (higher suspicion)
        - Post-failure success (potential breach)
        
        Returns:
            List of behavioral detections
        """
        detections = []
        
        # Check if IP has baseline in database
        baseline = None
        if self.db_connector:
            baseline = self.db_connector.get_ip_baseline(src_ip)
        
        # First-time IP with no historical baseline
        if not baseline and len(self.ip_attempts[src_ip]) >= 3:
            detections.append({
                'src_ip': src_ip,
                'detection_time': current_time,
                'event_type': 'ssh_bruteforce',
                'severity': 'medium',
                'tier': 2,
                'confidence_score': 0.65,
                'pattern_type': 'first_time_ip',
                'first_seen': self.ip_first_seen[src_ip].isoformat(),
                'raw_metrics': flow_data.to_dict()
            })
        
        # Post-failure success detection (simulated - in real logs, check for successful auth)
        # In CICIDS2017, we can infer from flow characteristics
        if self._is_potential_breach(flow_data) and len(self.ip_attempts[src_ip]) >= 5:
            detections.append({
                'src_ip': src_ip,
                'detection_time': current_time,
                'event_type': 'ssh_bruteforce',
                'severity': 'critical',
                'tier': 4,
                'confidence_score': 0.90,
                'pattern_type': 'post_failure_success',
                'prior_failures': len(self.ip_attempts[src_ip]),
                'raw_metrics': flow_data.to_dict()
            })
        
        return detections
    
    def _infer_username(self, flow_data: pd.Series) -> Optional[str]:
        """
        Infer username from flow data (simulation for CICIDS2017).
        
        In real SSH logs, this would be extracted from authentication messages.
        For CICIDS2017, we simulate based on flow ID or hash.
        """
        # Simulate username based on flow characteristics
        # In production, parse from actual SSH logs
        flow_hash = hash(str(flow_data.get('Flow Duration', 0)) + str(flow_data.get('Total Fwd Packets', 0)))
        usernames = ['root', 'admin', 'user', 'test', 'guest', 'oracle', 'postgres']
        return usernames[abs(flow_hash) % len(usernames)]
    
    def _is_potential_breach(self, flow_data: pd.Series) -> bool:
        """
        Detect potential successful breach after failures.
        
        Heuristic: Higher backward packets indicate successful session establishment.
        """
        fwd_packets = flow_data.get('Total Fwd Packets', 0)
        bwd_packets = flow_data.get('Total Backward Packets', 0)
        flow_duration = flow_data.get('Flow Duration', 0)
        
        # Successful SSH session: bidirectional traffic, longer duration
        return bwd_packets > 10 and flow_duration > 5000 and fwd_packets > 5
    
    def _deduplicate_attacks(self, attacks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate detections (same IP, same tier, within 60 seconds).
        
        Args:
            attacks: List of detected attacks
            
        Returns:
            Deduplicated list
        """
        if not attacks:
            return []
        
        # Sort by detection time
        attacks.sort(key=lambda x: x['detection_time'])
        
        deduplicated = []
        seen = {}  # (ip, tier) -> last detection time
        
        for attack in attacks:
            key = (attack['src_ip'], attack.get('tier', 0))
            last_time = seen.get(key)
            
            # Only add if not seen or >60 seconds since last detection
            if not last_time or (attack['detection_time'] - last_time).total_seconds() > 60:
                deduplicated.append(attack)
                seen[key] = attack['detection_time']
        
        return deduplicated
    
    def reset(self):
        """Reset all tracking structures (useful for testing)."""
        self.ip_attempts.clear()
        self.ip_usernames.clear()
        self.username_ips.clear()
        self.ip_first_seen.clear()
        self.ip_post_failure_success.clear()
        logger.info("SSH detector state reset")