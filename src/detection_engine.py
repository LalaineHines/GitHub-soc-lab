# src/detection_engine.py

import json

from detections.brute_force import (
    detect_brute_force
)

from detections.impossible_travel import (
    detect_impossible_travel
)

from detections.privilege_escalation import (
    detect_privilege_escalation
)

from detections.suspicious_process import (
    detect_suspicious_processes
)

from src.alert_manager import (
    AlertManager
)


def load_logs(filename):

    try:

        with open(filename, "r") as file:

            return json.load(file)
        
    except FileNotFoundError:

        print(
            f"Log file not found: "
            f"{filename}"
        )

        return []
    
    except json.JSONDecodeError:

        print(
            f"Invalid JSON in "
            f"{filename}"
        )

        return []
    

def main():

    print("\nStarting SOC Detection Engine...")
    print("=" * 40)

    # Load Logs

    authentication_logs = load_logs(
        "logs/authenication.json"
    )

    endpoint_logs = load_logs(
        "logs/endpoint.json"
    )

    # Run Detections

    brute_force_alerts = (
        detect_brute_force(
            authentication_logs
        )
    )

    impossible_travel_alerts = (
        detect_impossible_travel(
            authentication_logs
        )
    )

    privilege_alerts = (
        detect_privilege_escalation(
            authentication_logs
        )
    )

    process_alerts = (
        detect_suspicious_processes(
            endpoint_logs
        )
    )

    # Alert Manager

    manager = AlertManager()

    manager.add_alerts(
        brute_force_alerts
    )

    manager.add_alerts(
        impossible_travel_alerts
    )

    manager.add_alerts(
        privilege_alerts
    )

    manager.add_alerts(
        process_alerts
    )

    # Save Alerts

    manager.save_alerts()

    # Summary

    manager.print_summary()

    print(
        f"\nDetection complete. "
        f"{len(manager.alerts)} "
        f"alerts generated."
    )

    # Detection Statistics

    print("\n DETECTION STATISTICS")
    print("=" * 40)

    print(
        f"Brute Force Alerts: "
        f"{len(brute_force_alerts)}"
    )

    print(
        f"Impossible Travel Alerts: "
        f"{len(impossible_travel_alerts)}"
    )

    print(
        f"Privilege Escalation Alerts: "
        f"{len(privilege_alerts)}"
    )

    print(
        f"Suspicious Process Alerts: "
        f"{len(process_alerts)}"
    )

    # Mitre Attack Statistics

    print("\nMITRE ATT&CK STATISTICS")
    print("=" * 40)

    attack_techniques = {}

    for alert in manager.alerts:

        technique = alert.get(
            "mitre_attack",
            "Unknown"
        )

        attack_techniques[technique] = (
            attack_techniques.get(
                technique,
                0
            ) + 1
        )

    for technique, count in sorted(
        attack_techniques.items()
    ):
        
        print(
            f"{technique}: {count}"
        )


if __name__ == "__main__":
    main()