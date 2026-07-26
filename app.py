from flask import Flask, render_template, request, send_file
import os
import csv
import sqlite3
from parser import analyze_log
from database import create_database, save_analysis
from ai_engine import explain_alert

app = Flask(__name__)
create_database()
latest_result = None

UPLOAD_FOLDER = "logs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/")
def home():
    return render_template(
        "dashboard.html",
        total_logs=0,
        alerts=0,
        high=0,
        medium=0,
        low=0,
        threat_counts={},
        mitre_counts={},
        ioc_counts={},
        filename=""
    )


@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["logfile"]

    if file.filename != "":
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)
        global latest_result

        result = analyze_log(filepath)
        ai_explanation = "No threats detected."

        if result["threat_counts"]:

            first_threat = list(result["threat_counts"].keys())[0]

            event = first_threat[0]
            severity = first_threat[1]

            mitre = "Unknown"

            for item in result["mitre_counts"]:
                if item[0] == event:
                    mitre = item[1]
                    break

            ai_explanation = explain_alert(event, severity, mitre)

        latest_result = result
        save_analysis(
            result["total_logs"],
            result["alerts"],
           result["high"],
            result["medium"],
           result["low"]
        )
        

        return render_template(
            "dashboard.html",
            total_logs=result["total_logs"],
            alerts=result["alerts"],
            high=result["high"],
            medium=result["medium"],
            low=result["low"],
            threat_counts=result["threat_counts"],
            mitre_counts=result["mitre_counts"],
            ioc_counts=result["ioc_counts"],
            filename=file.filename,
            ai_explanation=ai_explanation
        )

    return "No file selected."

@app.route("/download_csv")
def download_csv():

    global latest_result

    if latest_result is None:
        return "Please upload a log file first."

    with open("analysis_report.csv", "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(["Mini SIEM Log Analysis Report"])
        writer.writerow([])

        writer.writerow(["Security Summary"])
        writer.writerow(["Total Logs", latest_result["total_logs"]])
        writer.writerow(["Alerts", latest_result["alerts"]])
        writer.writerow(["High Severity", latest_result["high"]])
        writer.writerow(["Medium Severity", latest_result["medium"]])
        writer.writerow(["Low Severity", latest_result["low"]])

        writer.writerow([])
        writer.writerow(["Detected Threats"])
        writer.writerow(["Event", "Severity", "Count"])

        for item, count in latest_result["threat_counts"].items():
            writer.writerow([item[0], item[1], count])

        writer.writerow([])
        writer.writerow(["MITRE ATT&CK Mapping"])
        writer.writerow(["Event", "MITRE ID", "Technique", "Count"])

        for item, count in latest_result["mitre_counts"].items():
            writer.writerow([item[0], item[1], item[2], count])

        writer.writerow([])
        writer.writerow(["IOC Matches"])
        writer.writerow(["IOC", "Count"])

        for ioc, count in latest_result["ioc_counts"].items():
            writer.writerow([ioc, count])

    return send_file(
        "analysis_report.csv",
        as_attachment=True
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)