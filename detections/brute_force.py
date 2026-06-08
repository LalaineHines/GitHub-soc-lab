# detections/brute_force.py

from collections import defaultdict
from datetime import datetime, timedelta


def detect_brute_force(logs, threshold=5, window_minutes=5):
    """
    Detects brute force login attempts.
    
    Args:
        logs (list): Authentication log events.
        threshold (int): Number of failed logins required.
        window_mintues (int): Detection time window.
        
    Returns:
        list: Generated alerts.
    """

    alerts = []

    failed_logins = defaultdict(list)

    # Collect failed login attempts
    for log in logs:

        if log.get("event") == "login_failed":

            user = log.get("user")
            timestamp = datetime.fromisoformat(log["timestamp"])

            failed_logins[user].append(timestamp)

        # Analyze each user
        for user, timestamps in failed_logins.items():

            timestamps.sort()

            for i in range(len(timestamps)):

                start_time = timestamps[i]
                end_time = start_time + timedelta(minutes=window_minutes)

                count = sum(
                    1
                    for ts in timestamps
                    if start_time <= ts <= end_time
                )

                if count >= threshold:

                    alert = {
                        "severity": "high",
                        "type": "Brute Force Login",
                        "user": user,
                        "timestamp": start_time.isoformat(),
                        "description": (
                            f"{count} failed login attempts detected "
                            f"within {window_minutes} minutes."
                        ),
                        "mitre_attack": "T1110",
                        "status": "open"
                    }

                    alerts.append(alert)

                    # Prevent duplicate alerts
                    break

    return alerts
