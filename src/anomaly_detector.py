from collections import defaultdict, deque
from datetime import timedelta

class BruteForceDetector:
    def __init__(self, threshold=5, window_minutes=2):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.ip_attempts = defaultdict(deque)  # {ip: [timestamps]}

    def report_attempt(self, ip, timestamp):
        # Remove old attempts outside time window
        while self.ip_attempts[ip] and timestamp - self.ip_attempts[ip][0] > self.window:
            self.ip_attempts[ip].popleft()
        # Add new attempt
        self.ip_attempts[ip].append(timestamp)
        # Check if exceeds threshold
        if len(self.ip_attempts[ip]) >= self.threshold:
            return True
        return False