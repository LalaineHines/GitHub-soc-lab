# src/report_generator.py

import json
from datetime import datetime


def load_alerts():

    try:

        with open(
            "alerts/alerts.json",
            "r"
        ) as file:

            return json.load(file)

    except FileNotFoundError:

        print(
            "alerts.json not found."
        )

        return []


def generate_report(alerts):

    report = []

    report.append(
        "# SOC Incident Report\n"
    )

    report.append(
        f"Generated: "
        f"{datetime.now().isoformat()}\n"
    )

    report.append(
        f"Total Alerts: "
        f"{len(alerts)}\n"
    )

    #
    # Severity Counts
    #

    critical = sum(
        1 for a in alerts
        if a.get("severity")
        == "critical"
    )

    high = sum(
        1 for a in alerts
        if a.get("severity")
        == "high"
    )

    medium = sum(
        1 for a in alerts
        if a.get("severity")
        == "medium"
    )

    low = sum(
        1 for a in alerts
        if a.get("severity")
        == "low"
    )

    report.append(
        "\n## Alert Summary\n"
    )

    report.append(
        f"- Critical: {critical}\n"
    )

    report.append(
        f"- High: {high}\n"
    )

    report.append(
        f"- Medium: {medium}\n"
    )

    report.append(
        f"- Low: {low}\n"
    )

    #
    # Alert Details
    #

    report.append(
        "\n## Alert Details\n"
    )

    for alert in alerts:

        report.append(
            f"\n### "
            f"{alert.get('type')}\n"
        )

        report.append(
            f"- Alert ID: "
            f"{alert.get('alert_id')}\n"
        )

        report.append(
            f"- Severity: "
            f"{alert.get('severity')}\n"
        )

        report.append(
            f"- Risk Score: "
            f"{alert.get('risk_score')}\n"
        )

        report.append(
            f"- MITRE ATT&CK: "
            f"{alert.get('mitre_attack')}\n"
        )

        report.append(
            f"- Description: "
            f"{alert.get('description')}\n"
        )

    return "".join(report)


def save_report(report):

    with open(
        "reports/latest_report.md",
        "w"
    ) as file:

        file.write(report)


def main():

    alerts = load_alerts()

    report = generate_report(
        alerts
    )

    save_report(report)

    print(
        "Incident report generated."
    )


if __name__ == "__main__":
    main()