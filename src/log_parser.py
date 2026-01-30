# import re
# from datetime import datetime

# def parse_auth_log_line(line):
#     # Match: "Failed password for invalid user admin from 192.168.1.100 port 22"
#     pattern = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password.*from (\d+\.\d+\.\d+\.\d+)"
#     match = re.search(pattern, line)
#     if match:
#         raw_time = f"{datetime.now().year} {match.group(1)}"
#         timestamp = datetime.strptime(raw_time, "%Y %b %d %H:%M:%S")
#         ip = match.group(2)
#         return {"timestamp": timestamp, "ip": ip, "event": "failed_login"}
#     return None

import re
from datetime import datetime


class LogParser:
    def __init__(self, log_path: str):
        self.log_path = log_path

    def parse(self):
        # Placeholder for now
        return None

    def parse_auth_log_line(self, line: str):
        pattern = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password.*from (\d+\.\d+\.\d+\.\d+)"
        match = re.search(pattern, line)

        if match:
            raw_time = f"{datetime.now().year} {match.group(1)}"
            timestamp = datetime.strptime(raw_time, "%Y %b %d %H:%M:%S")
            ip = match.group(2)

            return {
                "timestamp": timestamp,
                "ip": ip,
                "event": "failed_login",
            }

        return None

