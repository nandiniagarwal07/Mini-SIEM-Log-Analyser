def explain_alert(event, severity, mitre):

    severity = severity.lower()
    event = event.lower()

    explanation = ""

    # -------- Attack Detection --------

    if "failed" in event:
        explanation += "🔹 WHAT HAPPENED\n"
        explanation += "Multiple failed login attempts were detected.\n"
        explanation += "This may indicate a brute-force attack.\n\n"

    elif "powershell" in event:
        explanation += "🔹 WHAT HAPPENED\n"
        explanation += "PowerShell activity was detected.\n"
        explanation += "Attackers often misuse PowerShell to execute malicious commands.\n\n"

    elif "cmd" in event:
        explanation += "🔹 WHAT HAPPENED\n"
        explanation += "Command Prompt activity was detected.\n"
        explanation += "This may indicate unauthorized command execution.\n\n"

    elif "removed session" in event:
        explanation += "🔹 WHAT HAPPENED\n"
        explanation += "A user session was unexpectedly removed.\n"
        explanation += "This may indicate suspicious account activity.\n\n"

    elif "power off" in event:
        explanation += "🔹 WHAT HAPPENED\n"
        explanation += "The system experienced an unexpected power off event.\n"
        explanation += "This may indicate intentional shutdown or malicious activity.\n\n"

    elif "powering down" in event:
        explanation += "🔹 WHAT HAPPENED\n"
        explanation += "The system is shutting down unexpectedly.\n"
        explanation += "This may affect system availability.\n\n"

    else:
        explanation += "🔹 WHAT HAPPENED\n"
        explanation += "Suspicious security activity has been detected.\n\n"

    # -------- Severity --------

    explanation += "🔹 WHY IT MATTERS\n"

    if severity == "high":
        explanation += "Risk Level: HIGH\n"
        explanation += "Immediate investigation is strongly recommended.\n\n"

    elif severity == "medium":
        explanation += "Risk Level: MEDIUM\n"
        explanation += "This event should be reviewed by the SOC team.\n\n"

    else:
        explanation += "Risk Level: LOW\n"
        explanation += "Continue monitoring this activity.\n\n"

    # -------- MITRE --------

    explanation += "🔹 MITRE ATT&CK\n"
    explanation += f"Technique ID: {mitre}\n\n"

    # -------- Recommendation --------

    explanation += "🔹 RECOMMENDED ACTIONS\n"

    explanation += "✔ Review related logs.\n"
    explanation += "✔ Verify user activity.\n"
    explanation += "✔ Investigate the source of the event.\n"
    explanation += "✔ Isolate the affected machine if required.\n"
    explanation += "✔ Reset compromised credentials if necessary."

    return explanation