from collections import Counter
def analyze_log(filepath):

    total_logs = 0
    alerts = 0
    high = 0
    medium = 0
    low = 0

    alert_details = []
    mitre_mapping = []
    ioc_matches = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:

            for line in file:

                total_logs += 1
                line = line.lower()

                # ---------- IOC Detection ----------

                if "power off" in line:

                    ioc_matches.append("Unexpected Power Off")

                if "powering down" in line:

                    ioc_matches.append("System Shutdown Detected")

                if "removed session" in line:

                    ioc_matches.append("Multiple Session Removal")

                # ---------- High Severity ----------

                if "power off" in line:
                    alerts += 1
                    high += 1

                    alert_details.append({
                        "event": "Power Off",
                        "severity": "High"
                    })

                    mitre_mapping.append({
                        "event": "Power Off",
                        "mitre": "T1529",
                        "technique": "System Shutdown/Reboot"
                    })

                elif "powering down" in line:
                    alerts += 1
                    high += 1

                    alert_details.append({
                        "event": "Powering Down",
                        "severity": "High"
                    })

                    mitre_mapping.append({
                        "event": "Powering Down",
                        "mitre": "T1529",
                        "technique": "System Shutdown/Reboot"
                    })

                # ---------- Medium Severity ----------

                elif "removed session" in line:
                    alerts += 1
                    medium += 1

                    alert_details.append({
                        "event": "Removed Session",
                        "severity": "Medium"
                    })

                    mitre_mapping.append({
                        "event": "Removed Session",
                        "mitre": "T1078",
                        "technique": "Valid Accounts"
                    })

                # ---------- Low Severity ----------

                elif "logged out" in line:
                    alerts += 1
                    low += 1

                    alert_details.append({
                        "event": "Logged Out",
                        "severity": "Low"
                    })

                    mitre_mapping.append({
                        "event": "Logged Out",
                        "mitre": "T1078",
                        "technique": "Valid Accounts"
                    })

                # ---------- Normal Events (No Alert) ----------

                elif (
                    "new session" in line
                    or "new seat" in line
                    or "watching system buttons" in line
                ):
                    pass

    except FileNotFoundError:
        return None
    alerts = high + medium + low
    # Count repeated items

    threat_counts = Counter()

    for alert in alert_details:
        threat_counts[(alert["event"], alert["severity"])] += 1

    ioc_counts = Counter(ioc_matches)

    mitre_counts = Counter()

    for item in mitre_mapping:
        mitre_counts[(item["event"], item["mitre"], item["technique"])] += 1

    return {
        "total_logs": total_logs,
        "alerts": alerts,
        "high": high,
        "medium": medium,
        "low": low,
        "threat_counts": threat_counts,
        "mitre_counts": mitre_counts,
        "ioc_counts": ioc_counts
    }