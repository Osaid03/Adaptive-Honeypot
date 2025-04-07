from flask import Flask, Response, render_template, send_file
import time
import json
import csv
import os
import sys
from io import StringIO
import geoip2.database
app = Flask(__name__)

@app.route('/export/csv')
def export_csv():
    if not os.path.exists(LOG_FILE_PATH):
        return "Log file not found", 404

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "src_ip", "command", "classification"])

    with open(LOG_FILE_PATH, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("message") == "Command Classified":
                    writer.writerow([
                        data.get("timestamp", ""),
                        data.get("src_ip", ""),
                        data.get("command", ""),
                        data.get("classification", "")
                    ])
            except:
                continue

    output.seek(0)
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=honeypot_logs.csv"})

@app.route('/export/json')
def export_json():
    if not os.path.exists(LOG_FILE_PATH):
        return "Log file not found", 404

    logs = []
    with open(LOG_FILE_PATH, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("message") == "Command Classified":
                    logs.append({
                        "timestamp": data.get("timestamp", ""),
                        "src_ip": data.get("src_ip", ""),
                        "command": data.get("command", ""),
                        "classification": data.get("classification", "")
                    })
            except:
                continue

    return Response(json.dumps(logs, indent=2), mimetype="application/json")

@app.route("/geoip/<ip>")
def geo_lookup(ip):
    try:
        response = geo_reader.city(ip)
        return {
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "city": response.city.name,
            "country": response.country.name,
        }
    except:
        return {"latitude": 0, "longitude": 0}
app = Flask(__name__)

LOG_FILE_PATH = "logs/ssh_log.log"

def generate_log_stream():
    """Streams classified log entries and connection events in SSE format."""
    if not os.path.exists(LOG_FILE_PATH):
        print(f"❌ Log file not found at: {LOG_FILE_PATH}", file=sys.stderr)
        return

    with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if line:
                try:
                    data = json.loads(line)
                    print("📥 Parsed log line:", data)

                    message = data.get("message", "")
                    timestamp = data.get("timestamp", "N/A")
                    src_ip = data.get("src_ip", "N/A")
                    location_data = data.get("location", "Unknown")
                    if location_data == "Unknown":
                        loc = get_location(src_ip)
                        if loc:
                            city = loc.get("city") or ""
                            country = loc.get("country") or ""
                            location_data = f"{city}, {country}".strip(", ")
                    formatted_lines = []

                    if message == "Command Classified":
                        command = data.get("command", "N/A")
                        classification = data.get("classification", "N/A")

                        formatted_lines = [
                            f"[{timestamp}] 🌍 IP: {src_ip} ({location_data})",
                            f"💻 Command: {command}",
                            f"⚠️ Classification: {classification}",
                            "-" * 60,
                        ]

                    elif message == "SSH connection received":
                        formatted_lines = [
                            f"[{timestamp}] 🔌 New SSH connection from {src_ip} ({location_data})",
                            "-" * 60,
                        ]

                    elif message == "User attempting to authenticate":
                        username = data.get("username", "N/A")
                        formatted_lines = [
                            f"[{timestamp}] 🧪 Auth attempt for user: {username} from {src_ip} ({location_data})",
                        ]

                    elif message == "Authentication success":
                        username = data.get("username", "N/A")
                        formatted_lines = [
                            f"[{timestamp}] ✅ Authentication success for user: {username} from {src_ip} ({location_data})",
                        ]

                    elif message == "Authentication failed":
                        username = data.get("username", "N/A")
                        formatted_lines = [
                            f"[{timestamp}] ❌ Authentication failed for user: {username} from {src_ip} ({location_data})",
                        ]
                    
                    elif message == "Session Summary":
                        summary = data.get("summary", "")
                        formatted_lines = [summary]

                    if formatted_lines:
                        sse_data = "\n".join([f"data: {line}" for line in formatted_lines]) + "\n\n"
                        print("🚀 Yielding:", sse_data)
                        yield sse_data

                except json.JSONDecodeError as e:
                    print(f"❌ JSON parse error: {e}")
                    continue
                except Exception as e:
                    print(f"❌ Unknown error: {e}")
                    continue
            else:
                time.sleep(0.5)

@app.route('/stream')
def stream():
    print("🚀 Client connected to /stream")
    return Response(generate_log_stream(), mimetype="text/event-stream")

@app.route('/')
def index():
    return render_template("index.html")

def get_location(ip_address):
    try:
        geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = geo_reader.city(ip_address)
        location_data = {
            "country": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }
        geo_reader.close()
        return location_data
    except Exception as e:
        print(f"GeoIP lookup failed: {e}")
        return None

@app.route('/export/csv')
def export_csv():
    if not os.path.exists(LOG_FILE_PATH):
        return "Log file not found", 404

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "src_ip", "command", "classification"])

    with open(LOG_FILE_PATH, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("message") == "Command Classified":
                    writer.writerow([
                        data.get("timestamp", ""),
                        data.get("src_ip", ""),
                        data.get("command", ""),
                        data.get("classification", "")
                    ])
            except:
                continue

    output.seek(0)
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=honeypot_logs.csv"})

@app.route('/export/json')
def export_json():
    if not os.path.exists(LOG_FILE_PATH):
        return "Log file not found", 404

    logs = []
    with open(LOG_FILE_PATH, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("message") == "Command Classified":
                    logs.append({
                        "timestamp": data.get("timestamp", ""),
                        "src_ip": data.get("src_ip", ""),
                        "command": data.get("command", ""),
                        "classification": data.get("classification", "")
                    })
            except:
                continue

    return Response(json.dumps(logs, indent=2), mimetype="application/json")

@app.route("/geoip/<ip>")
def geo_lookup(ip):
    try:
        response = geo_reader.city(ip)
        return {
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "city": response.city.name,
            "country": response.country.name,
        }
    except:
        return {"latitude": 0, "longitude": 0}
    
    
if __name__ == '__main__':
    print("🚦 Flask app running...")
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)