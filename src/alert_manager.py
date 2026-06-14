import json
from datetime import datetime


class AlertManager:

    def __init__(self):

        self.alerts = []

    def add_alerts(self, new_alerts):

        if new_alerts:
            self.alerts.extend(new_alerts)

    def determine_severity(self, risk_score):

        if risk_score >= 90:
            return "critical"
        
        elif risk_score >= 75:
            return "high"
        
        elif risk_score >= 50:
            return "medium"
        
        return "low"
    
    def assign_ids(self):

        for index, alert in enumerate(
            self.alerts,
            start=1
        ):
            
            alert["alert_id"] = (
                f"SOC-{index:04}"
            )

    def sort_alerts(self):

        self.alerts.sort(
            key=lambda alert: (
                alert.get("risk_score", 0)
            ),
            reverse=True
        )

    def get_summary(self):

        summary = {
            "total": len(self.alerts),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for alert in self.alerts:

            severity = alert.get(
                "severity",
                "low",
            ).lower()

            if severity in summary:
                summary[severity] += 1

        return summary
    
    def save_alerts(
            self,
            filename="alerts/alerts.json"
    ):
        
        for alert in self.alerts:

            if "severity" not in alert:

                alert["severity"] = (
                    self.determine_severity(
                        alert.get(
                            "risk_score",
                            0
                        )
                    )
                )

        self.assign_ids()

        self.sort_alerts()

        with open(filename, "w") as file:

            json.dump(
                self.alerts,
                file,
                indent=4
            )

    def print_summary(self):

        summary = self.get_summary()

        print("\nSOC ALERT SUMMARY")
        print("=" * 30)

        print(
            f"Total Alerts: "
            f"{summary['total']}"
        )

        print(
            f"Critical: "
            f"{summary['critical']}"
        )

        print(
            f"High: "
            f"{summary['high']}"
        )

        print(
            f"Medium: "
            f"{summary['medium']}"
        )

        print(
            f"Low: "
            f"{summary['low']}"
        )

        print("=" * 30)