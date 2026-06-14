# detections/suspicious_process.py

def detect_suspicious_processes(logs):
    """
    Detect suspicious process execution events.
    
    Args:
        logs (list): Endpoint process execution logs
        
    Returns:
        list: Generated alerts
    """

    alerts = []

    suspicious_keywords = [
        "-encodedcommand",
        "invoke-webrequest",
        "downloadstring",
        "iex(",
        "certutil",
        "mimikatz",
        "psexec",
        "net user",
        "net localgroup administrators",
        "whoami /priv",
        "wmic",
        "bitsadmin"
    ]

    for log in logs:

        if log.get("event") != "process_execution":
            continue

        process = log.get("process_name", "").lower()
        command = log.get("command_line", "").lower()

        # Encoded Powershell

        if (
            process == "powershell.exe"
            and "-encoded command" in command
        ):
            
            alerts.append({
                "severity": "critical",
                "risk_score": 95,
                "type": "Encoded PowerShell",
                "process": process,
                "user": log.get("user"),
                "hostname": log.get("hostname"),
                "timestamp": log.get("timestamp"),
                "description": 
                    "Encoded PowerShell command detected",
                "mitre_attack": "T1059.001",
                "status": "open"
            })

        # Invoke-WebRequest

        elif (
            process == "powershell.exe"
            and "invoke-webrequest" in command
        ):
            
            alerts.append({
                "severity": "high",
                "risk_score": 75,
                "type": "PowerShell Web Download",
                "process": process,
                "user": log.get("user"),
                "hostname": log.get("hostname"),
                "timestamp": log.get("timestamp"),
                "description": 
                    "PowerShell download activity detected.",
                    "mitre_attack": "T1105",
                    "status": "open"
            })

        # DownloadString

        elif (
            process == "powershell.exe"
            and "downloadstring" in command
        ):
            
            alerts.append({
                "severity": "high",
                "risk_score": 80,
                "type": "PowerShell DownloadString",
                "process": process,
                "user": log.get("user"),
                "hostname": log.get("hostname"),
                "timestamp": log.get("timestamp"),
                "description": 
                    "PowerShell DownloadString usage detected.",
                "mitre_attack": "T1105",
                "status": "open"
            })

        # Certutil

        elif process == "certutil.exe":

            alerts.append({
                "severity": "high",
                "risk_score": 80,
                "type": "Certutil Download Activity",
                "process": process,
                "user": log.get("user"),
                "hostname": log.get("hostname"),
                "timestamp": log.get("timestamp"),
                "description":
                    "Certutil execution detected.",
                "mitre_attack": "T1105",
                "status": "open"
            })

        # Mimikatz

        elif "mimikatz" in process:

            alerts.append({
                "severity": "critical",
                "risk_score": 100,
                "type": "Mimikatz Execution",
                "process": process,
                "user": log.get("user"),
                "hostname": log.get("hostname"),
                "timestamp": log.get("timestamp"),
                "description": 
                    "Credential dumping tool detected.",
                "mitre_attack": "T1003",
                "status": "open"
            })

        # PsExec

        elif "psexec" in process:

            alerts.append({
                "severity": "high",
                "risk_score": 85,
                "type": "PsExec Usage",
                "process": process,
                "user": log.get("user"),
                "hostname": log.get("hostname"),
                "timestamp": log.get("timestamp"),
                "description": 
                    "Remote execution tool detected.",
                "mitre_attack": "T1021",
                "status": "open"
            })

        # Command Prompt Launching PowerShell

        elif (
            process == "cmd.exe"
            and "powershell" in command
        ):
            
            alerts.append({
                "severity": "medium",
                "risk_score": 60,
                "type": "Command Shell Launching PowerShell",
                "process": process,
                "user": log.get("user"),
                "hostname": log.get("hostname"),
                "timestamp": log.get("timestamp"),
                "description":
                    "cmd.exe launched POwerShell.",
                "mitre_attack": "T1059",
                "status": "open"
            })

        # Generic Suspicious Activity

    else:

        for keyword in suspicious_keywords:

            if keyword in command:

                alerts.append({
                    "severity": "medium",
                    "risk_score": 50,
                    "type": "Suspicious Command Activity",
                    "process": process,
                    "user": log.get("user"),
                    "hostname": log.get("hostname"),
                    "timestamp": log.get("timestamp"),
                    "description":
                        f"Suspicious keyword detected: {keyword}",
                    "mitre_attack": "T1059",
                    "status": "open"
                })

                break

    return alerts 