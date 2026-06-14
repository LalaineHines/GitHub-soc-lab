# src/log_generator.py

import json
import random
from datetime import datetime, timedelta


USERS = [
    "jsmith",
    "adoe",
    "mjones",
    "admin"
]

HOSTS = [
    "WIN-01",
    "WIN-02",
    "WEB-01"
]

CITIES = [
    "Seattle": (47.6062, -112.3321),
    "Chicago": (41.8781, -87.6298),
    "London": (51.5072, -0.1276) 
]


def generate_authentication_logs():

    logs = []

    base_time = datetime.now()

    # Normal Logins

    for i in range(20):

        city = random.choice(
            list(CITIES.keys())
        )

        lat, lon = CITIES[city]

        logs.append({
            "timestamp":
                (
                    base_time + 
                    timedelta(minutes=i)
                ).isoformat(),
            "event": "login_success",
            "user": random.choice(USERS),
            "city": city,
            "latitude": lat,
            "longitude": lon,
        })

        # Brute Force Attack

        for i in range(6):

            logs.append({
                "timestamp": 
                    (
                        base_time +
                        timedelta(minutes=30, seconds=i)
                    ).isoformat(),
                "event": "login_failed",
                "user": "jsmith",
                "ip": "203.0.113.10"
            })

        # Impossible Travel

        logs.append({
            "timestamp":
                (
                    base_time +
                    timedelta(hours=2)
                ).isoformat(),
            "event": "login_success",
            "user": "adoe",
            "city": "Seattle",
            "latitude": 47.6062,
            "longitude": -122.3321,
        })

        logs.append({
            "timestamp":
                (
                    base_time +
                    timedelta(hours=2, minutes=10)
                ).isoformat(),
            "event": "login_success",
            "user": "adoe",
            "city": "London",
            "latitude": 51.5072,
            "longitude": -0.1276,
        }) 

        # Privilege Escalation

        logs.append({
            "timestamp":
                (
                    base_time +
                    timedelta(hours=3)
                ).isoformat()
            "event": "privilege_change",
            "user": "mjones",
            "old_role": "user",
            "new_role": "admin"
        })

        # Admin Account Creation

        logs.append({
            "timestamp": 
                (
                    base_time +
                    timedelta(hours=4)
                ).isoformat()
            "event": "account_created",
            "user": "backup_admin",
            "role": "admin"
        })

        return logs
    
def generate_endpoint_logs():

    logs = []

    base_time = datetime.now()

    # Normal Processes

    logs.append({
        "timestamp": base_time.isoformat(),
        "event": "process_execution",
        "user": "jsmith",
        "hostname": "WIN-01",
        "process_name": "notepad.exe",
        "comand_line": "notepad.exe"
    })

    # Encoded PowerShell

    logs.append({
        "timestamp": 
            (
                base_time +
                timedelta(minutes=5)
            ).isoformat(),
        "event": "process_execution",
        "user": "admin",
        "hostname": "WIN-01",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand SQBFAFgA"
    })

    # Mimikatz

    logs.append({
        "timestamp": 
            (
                base_time +
                timedelta(minutes=10)
            ).isoformat(),
            "event": "process_execution",
            "user": "admin",
            "hostname": "WIN-02",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe"
    })

    return logs

def save_logs():

    auth_logs = (
        generate_authentication_logs()
    )

    endpoint_logs = (
        generate_endpoint_logs()
    )

    with open(
        "logs/authentication.json",
        "w"
    ) as file:
        
        json.dump(
            auth_logs,
            file,
            indent=4
        )

    with open(
        "logs/endpoint.json",
        "w"
    ) as files:
        
        json.dump(
            endpoint_logs,
            file,
            indent=4
        )

    print(
        "SOC logs generated successfully."
    )


if __name__ == "__main__":
    save_logs()