# detections/impossible_travel.py

from datetime import datetime
from math import radians, sin, cos, sqrt, atan2


def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Calculate distance between two coordinates in kilometers.
    """

    earth_radius = 6371

    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)

    a = (
        sin(dlat / 2) ** 2
        + cos(radians(lat1))
        * cos(radians(lat2))
        * sin(dlon / 2) ** 2 
    )

    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return earth_radius * c


def detect_impossible_travel(logs, speed_threshold=900):
    """
    Detect impossible travel events.

    speed_threshold:
    Maximum reasonable travel speed in km/h.
    """

    alerts = []

    user_logins = {}

    for log in logs:

        if log.get("event") != "login_success":
            continue

        user = log.get("user")

        timestamp = datetime.fromisoformat(log["timestamp"])

        latitude = log.get("latitude")
        longitude = log.get("longitude")

        if user not in user_logins:
            user_logins[user] = []

        user_logins[user].append(
            {
                "timestamp": timestamp,
                "latitude": latitude,
                "longitude": longitude
            }
        )

    for user, entries in user_logins.items():

        entries.sort(key=lambda x: x["timestamp"])

        for i in range(len(entries) - 1):

            current = entries[i]
            next_entry = entries[i + 1]

            distance = calculate_distance(
                current["latitude"],
                current["longitude"],
                next_entry["latitude"],
                next_entry["longitude"]
            )

            time_diff = (
                next_entry["timestamp"] - 
                current["timestamp"]
            ).total_seconds() / 3600

            if time_diff <= 0:
                continue

            speed = distance / time_diff

            if speed > speed_threshold:

                alert = {
                    "severity": "critical",
                    "type": "Impossible Travel",
                    "user": user,
                    "timestamp": next_entry[
                        "timestamp"
                    ].isoformat(),
                    "description": (
                        f"user appeared to travel "
                        f"{distance:.0f} km at "
                        f"{speed:.0f} km/h."
                    ),
                    "mitre_attack": "T1078",
                    "status": "open"
                }

                alerts.append(alert)

    return alerts