"""
SSH Brute-Force Detection Module.

Implements detection logic based on Khan & Rahman (2023) baseline:
>= 5 connection attempts from same Source IP to port 22 within 2 minutes.
"""

import pandas as pd
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

class SSHBruteForceDetector:
    """
    Detects SSH brute-force attacks using sliding time-window analysis.
    """
    
    def __init__(self, threshold: int = 5, window_minutes: int = 2):
        """
        Initialize detector with threshold and time window.
        
        Args:
            threshold: Number of attempts required to trigger alert (default: 5)
            window_minutes: Time window in minutes for detection (default: 2)
        """
        self.threshold = threshold
        self.window_minutes = window_minutes
        
    def detect(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Analyze dataframe for brute-force patterns.
        
        Args:
            df: DataFrame containing 'source_ip' and 'timestamp' columns.
                Assumes data is already filtered for SSH traffic.
                
        Returns:
            List of detected attacks with details.
        """
        if df.empty:
            return []
            
        attacks = []
        
        try:
            # Ensure timestamp is datetime and sort
            df = df.copy()
            if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                
            df = df.sort_values('timestamp')
            
            # Group by Source IP
            grouped = df.groupby('source_ip')
            
            for source_ip, group in grouped:
                # We need to find if there are >= threshold events within window
                # Using a rolling count on time index
                
                # Set timestamp as index for rolling operation
                group_indexed = group.set_index('timestamp')
                
                # Resample or reindex isn't efficient for sliding window of arbitrary events.
                # Instead, for each event, we can check count of events in the previous window.
                # Or use rolling(window='2min').count()
                
                # Create a dummy column to count
                group_indexed['attempt'] = 1
                
                # Rolling count in the time window (closed='right' means window ends at current row)
                # 'min' is the offset alias for minutes
                rolling_counts = group_indexed['attempt'].rolling(
                    f'{self.window_minutes}min', 
                    closed='right'
                ).sum()
                
                # Identify points where threshold is breached
                # Filter indices where count >= threshold
                breaches = rolling_counts[rolling_counts >= self.threshold]
                
                if not breaches.empty:
                    # We have detections. 
                    # To avoid multiple alerts for the same burst, we can pick the first one 
                    # or report clusters. For simplicity and "real-time" simulation, 
                    # we report distinct detection events.
                    
                    # Let's extract the first time it breached in a continuous sequence, 
                    # or just report all unique breach moments. 
                    # For a summary report, let's group breaches that are close together.
                    
                    # For this implementation, we'll return the detecting timestamp (when the Nth attempt happened)
                    for timestamp, count in breaches.items():
                        attacks.append({
                            'source_ip': source_ip,
                            'detection_time': timestamp,
                            'attempt_count': int(count),
                            'window_minutes': self.window_minutes
                        })
            
            # Sort detected attacks by time
            attacks.sort(key=lambda x: x['detection_time'])
            
            # De-duplicate attacks: if we detect an attack at T, and another at T+1s with count+1,
            # it's part of the same ongoing attack. 
            # We might want to alert once per "session" or continuously.
            # Khan & Rahman implies "If condition met -> Alert".
            # We will return all breaches but the AlertManager can choose to suppress duplicates.
            
            return attacks
            
        except Exception as e:
            logger.error(f"Error during detection analysis: {e}")
            return []
