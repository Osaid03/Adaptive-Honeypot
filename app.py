from flask import Flask, Response, render_template, send_file, redirect, request, jsonify
import time
import json
import csv
import os
import sys
import pandas as pd
import datetime
from io import StringIO
import geoip2.database
import subprocess

app = Flask(__name__)

# Try to load GeoIP database, but provide fallback if it fails
try:
    geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
    print("✅ GeoIP database loaded successfully")
    geo_db_available = True
except Exception as e:
    print(f"⚠️ GeoIP database error: {e}")
    print("⚠️ Map functionality will be limited")
    geo_db_available = False

LOG_FILE_PATH = "logs/ssh_log.log"
ANOMALOUS_COMMANDS_FILE = "logs/anomalous_commands.csv"
LABELED_DATA_FILE = "model_assets/labeled_anomalies.csv"
ATTACK_DATA_FILE = "model_assets/attack_data.csv"

# Create necessary directories if they don't exist
os.makedirs('logs', exist_ok=True)
os.makedirs('model_assets', exist_ok=True)

# Ensure anomalous commands file exists
if not os.path.exists(ANOMALOUS_COMMANDS_FILE):
    with open(ANOMALOUS_COMMANDS_FILE, 'w') as f:
        pass  # Create empty file

# Track processed anomalies to avoid duplicate notifications
processed_anomalies = set()

def get_location(ip_address):
    try:
        if not geo_db_available:
            return {
                "country": "Unknown",
                "city": "Unknown",
                "latitude": 0,
                "longitude": 0,
            }

        response = geo_reader.city(ip_address)
        location_data = {
            "country": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }
        return location_data
    except Exception as e:
        print(f"GeoIP lookup failed: {e}")
        return None

@app.route("/geoip/<ip>")
def geo_lookup(ip):
    return get_location(ip) or {"latitude": 0, "longitude": 0}

def check_for_anomalous_commands():
    """Check for new anomalous commands and send them to the event stream"""
    global processed_anomalies

    if not os.path.exists(ANOMALOUS_COMMANDS_FILE):
        return []

    try:
        # Read anomalous commands file
        anomalies_df = pd.read_csv(ANOMALOUS_COMMANDS_FILE, header=None, names=['command'])
        anomalies = anomalies_df['command'].tolist()

        # Find new anomalies that haven't been processed yet
        new_anomalies = [cmd for cmd in anomalies if cmd not in processed_anomalies]

        # Mark these as processed
        processed_anomalies.update(new_anomalies)

        return new_anomalies
    except Exception as e:
        print(f"Error checking anomalous commands: {e}")
        return []

def generate_log_stream():
    if not os.path.exists(LOG_FILE_PATH):
        print(f"❌ Log file not found at: {LOG_FILE_PATH}", file=sys.stderr)
        return

    with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)

        # Send initial connection message
        yield "data: 🔌 Connected to log stream\n\n"

        # Track last connection message time to avoid too many
        last_connection_msg_time = time.time()
        # Set throttle interval to 30 seconds
        connection_msg_throttle = 30

        while True:
            # Check if we need to send a keepalive message
            current_time = time.time()
            send_keepalive = False

            # Only send keepalive messages every 30 seconds
            if current_time - last_connection_msg_time > connection_msg_throttle:
                send_keepalive = True
                last_connection_msg_time = current_time

            # Check for new log lines
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
                # Only send a keepalive message if it's time (based on our throttle check at the top)
                if send_keepalive:
                    # Use a silent keepalive that doesn't show in the UI
                    yield "data: \n\n"

                time.sleep(0.5)

@app.route('/stream')
def stream():
    print("🚀 Client connected to /stream")
    return Response(generate_log_stream(), mimetype="text/event-stream")

@app.route('/')
def index():
    return render_template("index.html")

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

# ===== ANOMALY REVIEW INTERFACE =====

@app.route('/anomalies')
def anomalies():
    # Load anomalous commands
    if os.path.exists(ANOMALOUS_COMMANDS_FILE):
        try:
            # Read as a single column CSV without header
            anomalies_df = pd.read_csv(ANOMALOUS_COMMANDS_FILE, header=None, names=['command'])
            # Remove duplicates
            anomalies_df = anomalies_df.drop_duplicates()
            anomalies = anomalies_df['command'].tolist()
        except Exception as e:
            anomalies = []
            print(f"Error reading anomalies file: {e}")
    else:
        anomalies = []

    # Check if labeled data file exists
    if not os.path.exists(LABELED_DATA_FILE):
        # Create it with headers
        pd.DataFrame(columns=['command', 'label', 'date_labeled']).to_csv(LABELED_DATA_FILE, index=False)

    # Load already labeled commands to avoid showing them again
    if os.path.exists(LABELED_DATA_FILE):
        labeled_df = pd.read_csv(LABELED_DATA_FILE)
        labeled_commands = labeled_df['command'].tolist()
        # Filter out already labeled commands
        anomalies = [cmd for cmd in anomalies if cmd not in labeled_commands]

    return render_template('review_anomalies.html', anomalies=anomalies)

@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    """API endpoint to get anomalous commands for AJAX refresh"""
    # Load anomalous commands
    if os.path.exists(ANOMALOUS_COMMANDS_FILE):
        try:
            # Read as a single column CSV without header
            anomalies_df = pd.read_csv(ANOMALOUS_COMMANDS_FILE, header=None, names=['command'])
            # Remove duplicates
            anomalies_df = anomalies_df.drop_duplicates()
            anomalies = anomalies_df['command'].tolist()
        except Exception as e:
            anomalies = []
            print(f"Error reading anomalies file: {e}")
    else:
        anomalies = []

    # Load already labeled commands to avoid showing them again
    if os.path.exists(LABELED_DATA_FILE):
        labeled_df = pd.read_csv(LABELED_DATA_FILE)
        labeled_commands = labeled_df['command'].tolist()
        # Filter out already labeled commands
        anomalies = [cmd for cmd in anomalies if cmd not in labeled_commands]

    return jsonify({"anomalies": anomalies})

@app.route('/api/label', methods=['POST'])
def api_label_anomalies():
    """API endpoint to label anomalies via AJAX"""
    data = request.json
    commands = data.get('commands', [])
    labels = data.get('labels', [])

    if len(commands) != len(labels):
        return jsonify({"success": False, "message": "Commands and labels must have the same length"})

    # Create dataframe with labeled data
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_rows = []
    for cmd, label in zip(commands, labels):
        if label in ['BENIGN', 'SUSPICIOUS', 'MALICIOUS']:
            data_rows.append({
                'command': cmd,
                'label': label,
                'date_labeled': now
            })

    # Append to labeled data file
    if data_rows:
        new_df = pd.DataFrame(data_rows)
        if os.path.exists(LABELED_DATA_FILE):
            labeled_df = pd.read_csv(LABELED_DATA_FILE)
            combined_df = pd.concat([labeled_df, new_df])
            combined_df.to_csv(LABELED_DATA_FILE, index=False)
        else:
            new_df.to_csv(LABELED_DATA_FILE, index=False)

        return jsonify({"success": True, "message": f"Successfully labeled {len(data_rows)} commands"})
    else:
        return jsonify({"success": False, "message": "No valid labels provided"})

@app.route('/label', methods=['POST'])
def label_anomalies():
    """Traditional form submission endpoint (fallback for non-JS browsers)"""
    commands = request.form.getlist('command')
    labels = request.form.getlist('label')

    # Create dataframe with labeled data
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = []
    for cmd, label in zip(commands, labels):
        if label in ['BENIGN', 'SUSPICIOUS', 'MALICIOUS']:
            data.append({
                'command': cmd,
                'label': label,
                'date_labeled': now
            })

    # Append to labeled data file
    if data:
        new_df = pd.DataFrame(data)
        if os.path.exists(LABELED_DATA_FILE):
            labeled_df = pd.read_csv(LABELED_DATA_FILE)
            combined_df = pd.concat([labeled_df, new_df])
            combined_df.to_csv(LABELED_DATA_FILE, index=False)
        else:
            new_df.to_csv(LABELED_DATA_FILE, index=False)

    return redirect('/anomalies')

@app.route('/api/integrate', methods=['POST'])
def integrate_data():
    # Integrate labeled anomalies into training dataset
    if os.path.exists(LABELED_DATA_FILE):
        labeled_df = pd.read_csv(LABELED_DATA_FILE)
        if not labeled_df.empty:
            # Load original training data
            if os.path.exists(ATTACK_DATA_FILE):
                train_df = pd.read_csv(ATTACK_DATA_FILE)
                # Combine datasets
                combined_df = pd.concat([train_df, labeled_df[['command', 'label']]])
                # Remove duplicates (keep first occurrence)
                combined_df = combined_df.drop_duplicates(subset=['command'], keep='first')
                # Save back to training file
                combined_df.to_csv(ATTACK_DATA_FILE, index=False)

                # Clear the processed anomalies file
                if os.path.exists(ANOMALOUS_COMMANDS_FILE):
                    # Create backup
                    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    backup_file = f"logs/anomalous_commands_backup_{now}.csv"
                    os.rename(ANOMALOUS_COMMANDS_FILE, backup_file)
                    # Create new empty file
                    open(ANOMALOUS_COMMANDS_FILE, 'w').close()

                # Also clear the processed anomalies tracking file
                processed_file = "logs/processed_anomalies.csv"
                if os.path.exists(processed_file):
                    os.remove(processed_file)

                # Reset the processed_anomalies set
                global processed_anomalies
                processed_anomalies = set()

                return jsonify({"success": True, "message": "Data integrated successfully. You can now retrain the model."})
            else:
                return jsonify({"success": False, "message": "Error: Training data file not found."})
        else:
            return jsonify({"success": False, "message": "No labeled data to integrate."})
    else:
        return jsonify({"success": False, "message": "Error: Labeled data file not found."})

@app.route('/api/retrain', methods=['POST'])
def api_retrain():
    # Execute the retrain_model_inline.py script instead of retrain_model.py
    try:
        result = subprocess.run(["python", "retrain_model_inline.py"],
                            capture_output=True, text=True, check=True)
        return jsonify({
            "success": True,
            "message": "Model retraining completed successfully.",
            "details": result.stdout
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            "success": False,
            "message": f"Error retraining model: {str(e)}",
            "details": e.stderr
        })

@app.route('/retrain')
def retrain():
    return render_template('retrain.html')

@app.route('/api/add_anomaly', methods=['POST'])
def add_test_anomaly():
    """API endpoint to manually add a test anomalous command"""
    data = request.json
    command = data.get('command', '')

    if not command:
        return jsonify({"success": False, "message": "No command provided"})

    # Append to anomalous commands file
    with open(ANOMALOUS_COMMANDS_FILE, 'a') as f:
        f.write(f"{command}\n")

    return jsonify({"success": True, "message": f"Added anomalous command: {command}"})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')