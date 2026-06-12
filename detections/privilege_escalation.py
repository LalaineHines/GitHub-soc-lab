# detections/privilege_escalation.py

from datetime import datetime

def detect_privilege_escalation(logs):
    """
    Detects user privilege escalation events.
    
    Args:
        logs (list): Log events.
        
    Returns:
        list: Generated alerts.
    """

    alerts = []
    
    privileged_roles = [
        "admin",
        "administrator",
        "domain_admin",
        "root",
        "superuser"
    ]

    for log in logs:

        event = log.get("event")

        # Existing account promoted
        if event == "privilege_change":

            old_role = log.get("old_role", "").lower()
            new_role = log.get("new_role", "").lower()

            if (
                new_role in privileged_roles
                and old_role != new_role
            ):

                alerts.append({
                    "severity": "high",
                    "type": "Privilege Escalation",
                    "user": log.get("user"),
                    "timestamp": log.get("timestamp"),
                    "description":
                        f"User {log.get('user')} was promoted "
                        f"from {old_role} to {new_role}.",
                    "mitre_attack": "T1098",
                    "status": "open"
                })

        # New privileged account created
        elif event == "account_created":

            role = log.get("role", "").lower()

            if role in privileged_roles:

                alerts.append({
                    "severity": "critical",
                    "type": "Privileged Account Created",
                    "user": log.get("user"),
                    "timestamp": log.get("timestamp"),
                    "description":
                        f"New privileged account "
                        f"{log.get('user')} was created "
                        f"with role {role}.",
                    "mitre_attack": "T1136",
                    "status": "open"
                })

    return alerts