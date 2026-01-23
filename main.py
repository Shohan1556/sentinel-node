# from src.log_parser import LogParser
# from src.anomaly_detector import AnomalyDetector
# from src.alert_manager import AlertManager
# from src.config import CONFIG

# def main():
#     print("Sentinel Node starting...")
#     # Initialization logic here
#     pass

# if __name__ == "__main__":
#     main()
# from src.log_parser import parse_auth_log_line
# from src.anomaly_detector import BruteForceDetector
# import sys

# def main(log_file_path="data/raw/sample_auth.log"):
#     print("Sentinel Node starting...")
#     detector = BruteForceDetector(threshold=5, window_minutes=2)
#     alerts = []

#     with open(log_file_path, 'r') as f:
#         for line_num, line in enumerate(f, 1):
#             event = parse_auth_log_line(line)
#             if event:
#                 is_attack = detector.report_attempt(event["ip"], event["timestamp"])
#                 if is_attack:
#                     alert = f"[ALERT] Brute-force detected from {event['ip']} at {event['timestamp']}"
#                     print(alert)
#                     alerts.append(alert)
#     return alerts

# if __name__ == "__main__":
#     main()

from src.log_parser import LogParser
from src.anomaly_detector import BruteForceDetector


def main(log_file_path="data/raw/sample_auth.log"):
    print("Sentinel Node starting...")

    parser = LogParser(log_file_path)
    detector = BruteForceDetector(threshold=5, window_minutes=2)
    alerts = []

    with open(log_file_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            event = parser.parse_auth_log_line(line)
            if event:
                is_attack = detector.report_attempt(
                    event["ip"], event["timestamp"]
                )
                if is_attack:
                    alert = (
                        f"[ALERT] Brute-force detected from "
                        f"{event['ip']} at {event['timestamp']}"
                    )
                    print(alert)
                    alerts.append(alert)

    return alerts


if __name__ == "__main__":
    main()
