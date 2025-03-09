#!/usr/bin/env python3
"""
SSH Honeypot Server With In-House ML Command Classification and Admin Session Summary

This server listens on an SSH port and interacts with connecting attacker clients.
Each command from an attacker is processed via a trained LSTM model, Q‐table, and tokenizer,
classifying it as BENIGN, SUSPICIOUS, or MALICIOUS. All commands (with their results)
are globally recorded. Meanwhile, the defender (administrator) who is running the honeypot
server can type "S" (followed by Enter) into the server console to obtain a summary of all
attacker activity.
Logs are written in a structured JSON format.
"""
import argparse
import asyncio
import asyncssh
import configparser
import logging
import datetime
import socket
import os
import sys
import traceback
import uuid
import json
from base64 import b64encode
from ml_handler import analyze_command, classify_command
import geoip2.database  # Import GeoIP2 correctly

# --- ML Imports & Model Loading ---
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")


def get_location(ip_address):  # Your new function
    try:
        geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = geo_reader.city(ip_address)
        location_data = {
            "country": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude
        }
        geo_reader.close()
        return location_data
    except Exception as e:
        print(f"GeoIP lookup failed: {e}")
        return None


# Define dataset directory
DATASET_DIR = "datasets"

def load_ml_models(config):
    ml_config = config['ml']
    lstm_model_file = os.path.join(DATASET_DIR, ml_config.get('lstm_model_file', 'lstm_attack_model.h5'))
    q_table_file = os.path.join(DATASET_DIR, ml_config.get('q_table_file', 'q_table.npy'))
    tokenizer_file = os.path.join(DATASET_DIR, ml_config.get('tokenizer_file', 'tokenizer.json'))
    max_seq_length = ml_config.getint('max_sequence_length', 20)

    if not os.path.exists(lstm_model_file):
        raise FileNotFoundError(f"LSTM model file '{lstm_model_file}' not found!")
    lstm_model = tf.keras.models.load_model(lstm_model_file)
    print(f"LSTM model loaded from '{lstm_model_file}'")

    if not os.path.exists(q_table_file):
        raise FileNotFoundError(f"Q-table file '{q_table_file}' not found!")
    Q_table = np.load(q_table_file)
    print(f"Q-table loaded from '{q_table_file}'")

    if not os.path.exists(tokenizer_file):
        raise FileNotFoundError(f"Tokenizer file '{tokenizer_file}' not found!")
    with open(tokenizer_file, 'r') as f:
        tokenizer_data = json.load(f)
        tokenizer_json_str = json.dumps(tokenizer_data)
        tokenizer = tf.keras.preprocessing.text.tokenizer_from_json(tokenizer_json_str)
    print(f"Tokenizer loaded from '{tokenizer_file}'")

    return lstm_model, Q_table, tokenizer, max_seq_length

# Load models when starting the server
config = configparser.ConfigParser()
config.read("config.ini")
lstm_model, Q_table, tokenizer, max_seq_length = load_ml_models(config)



def session_summary(command_log):
    total = len(command_log)
    if total == 0:
        return "No commands issued."
    malicious = sum(1 for cmd in command_log if cmd['classification'] == "MALICIOUS")
    suspicious = sum(1 for cmd in command_log if cmd['classification'] == "SUSPICIOUS")
    benign = sum(1 for cmd in command_log if cmd['classification'] == "BENIGN")
    risk_score = (malicious + 0.5 * suspicious) / total * 100
    summary_text = (f"Session Summary: {total} total commands. "
                    f"Benign: {benign}, Suspicious: {suspicious}, Malicious: {malicious}. "
                    f"Risk Score: {risk_score:.1f}%")
    return summary_text

# --- Logging Utilities ---
class JSONFormatter(logging.Formatter):
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "task_name": getattr(record, 'task_name', '-'),
            "src_ip": getattr(record, 'src_ip', '-'),
            "src_port": getattr(record, 'src_port', '-'),
            "dst_ip": getattr(record, 'dst_ip', '-'),
            "dst_port": getattr(record, 'dst_port', '-'),
            "message": record.getMessage(),
            "sensor_name": self.sensor_name,
            "sensor_protocol": "ssh"
        }
        for key, value in record.__dict__.items():
            if key not in log_record and key not in ('args', 'msg'):
                log_record[key] = value
        return json.dumps(log_record)

class ContextFilter(logging.Filter):
    def filter(self, record):
        task = asyncio.current_task()
        record.task_name = task.get_name() if task else "-"
        record.src_ip = getattr(thread_local, 'src_ip', '-')
        record.src_port = getattr(thread_local, 'src_port', '-')
        record.dst_ip = getattr(thread_local, 'dst_ip', '-')
        record.dst_port = getattr(thread_local, 'dst_port', '-')
        return True

class ThreadLocal:
    pass

thread_local = ThreadLocal()

# --- Rest of your server code ---

if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read("config.ini")

    # Ensure load_ml_models is called with the config argument
    global_lstm_model, global_Q_table, global_tokenizer, global_max_seq_length = load_ml_models(config)

    # Continue with your server setup and start handling connections


    # Continue with your server setup and start handling connections


def get_user_accounts(config: configparser.ConfigParser) -> dict:
    if 'user_accounts' not in config or len(config.items('user_accounts')) == 0:
        raise ValueError("No user accounts found in configuration file.")
    return dict(config.items('user_accounts'))

# Global list tracking all attacker commands across sessions.
global_command_database = []

# --- SSH Server for Authentication ---
class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):  # Make sure this is indented properly
        peername = conn.get_extra_info('peername')
        src_ip, src_port = (peername[:2] if peername else ('-', '-'))
        sockname = conn.get_extra_info('sockname')
        dst_ip, dst_port = (sockname[:2] if sockname else ('-', '-'))

        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port

        # Get attacker's location
        location = get_location(src_ip)

        # Log attack origin
        logger.info(f"New Attack from {location} - IP: {src_ip}", extra={
            "src_ip": src_ip,
            "src_port": src_port,
            "location": location,
            "dst_ip": dst_ip,
            "dst_port": dst_port
        })

        print(f"🚨 New Attack from {location} (IP: {src_ip})")  # Print for monitoring



    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        logger.info("Auth Attempt", extra={"username": username, "password": password})
        return True

# --- Process-Based Session Handler for Attackers ---
async def handle_client(process):
    # Create a unique session ID.
    session_id = f"session-{uuid.uuid4()}"
    logger.info("Session Start", extra={"session": session_id})
    process.stdout.write("Welcome to XYZ Game Development Server!\n")
    process.stdout.write("> ")
    await process.stdout.drain()

    command_log = []  # Record commands for this session

    async for line in process.stdin:
        command = line.strip()
        if not command:
            process.stdout.write("> ")
            await process.stdout.drain()
            continue

        # Log received command
        logger.info("User Command Received", extra={"command": command})

        # ✅ ML Classification: Analyze and classify command
        prediction = analyze_command(command)  # Get LSTM prediction
        classification = classify_command(prediction)  # Determine command type

        # ✅ Log classification result
        cmd_entry = {"command": command, "classification": classification}
        print("DEBUG: Recording:", command, "->", classification)
        command_log.append(cmd_entry)
        global_command_database.append(cmd_entry)

        logger.info("Command Classified", extra={
            "command": command,
            "classification": classification,
            "prediction": str(prediction.tolist()) if prediction is not None else "None"
        })

        # ✅ Respond based on classification
        if classification == "MALICIOUS":
            process.stdout.write("⚠️ Security alert! Unauthorized actions detected.\n")
        else:
            process.stdout.write(f"Executing: {command}\n")

        # ✅ Exit if the attacker types "exit" or "quit"
        if command.lower() in ["exit", "quit"]:
            process.stdout.write("Goodbye!\n")
            await process.stdout.drain()
            break

        process.stdout.write("> ")
        await process.stdout.drain()

    logger.info("Session End", extra={"session": session_id})
    process.exit(0)


# --- Administrator Monitor Task ---
async def monitor_admin():
    """
    This task runs in the main event loop. It continuously reads input from the
    defender (admin) via sys.stdin. If the admin types 'S' (or 's') and presses Enter,
    a summary of all collected attacker commands (from global_command_database) is generated and printed.
    """
    loop = asyncio.get_event_loop()
    while True:
        # Use run_in_executor to call input() without blocking the event loop.
        admin_input = await loop.run_in_executor(None, sys.stdin.readline)
        if admin_input is None:
            continue
        admin_input = admin_input.strip()
        if admin_input.upper() == "S":
            summary = session_summary(global_command_database)
            print("\n=== DEFENDER SESSION SUMMARY ===")
            print(summary)
            print("================================\n")
        # You may insert other admin commands as needed.

# --- Start the SSH Server ---
async def start_server(config: configparser.ConfigParser,
                       tokenizer, lstm_model, Q_table, max_seq_length):
    port = config['ssh'].getint("port", 8022)
    host_priv_key = config['ssh'].get("host_priv_key", "ssh_host_key")
    if not os.path.exists(host_priv_key):
        os.system(f"ssh-keygen -f {host_priv_key} -N '' -t rsa -b 2048")
    await asyncssh.listen(
        host="0.0.0.0",
        port=port,
        server_factory=MySSHServer,
        process_factory=handle_client,
        server_host_keys=[host_priv_key],
        server_version=config['ssh'].get("server_version_string", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3")
    )
    logger.info("SSH Honeypot Server is running", extra={"port": port})
    await asyncio.Event().wait()

# --- MAIN ENTRY POINT ---
def main():
    try:
        parser = argparse.ArgumentParser(description='Start the SSH honeypot server with admin session summary.')
        parser.add_argument('-c', '--config', type=str, default=None, help='Path to configuration file')
        parser.add_argument('-u', '--user-account', action='append', help='User account (username=password)')
        args = parser.parse_args()

        config = configparser.ConfigParser()
        if args.config:
            if not os.path.exists(args.config):
                print(f"Error: The specified config file '{args.config}' does not exist.", file=sys.stderr)
                sys.exit(1)
            config.read(args.config)
        else:
            default_config = "config.ini"
            if os.path.exists(default_config):
                config.read(default_config)
            else:
                config['honeypot'] = {'log_file': 'ssh_log.log', 'sensor_name': socket.gethostname()}
                config['ssh'] = {
                    'port': '8022',
                    'host_priv_key': 'ssh_host_key',
                    'server_version_string': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3'
                }
                config['ml'] = {
                    'lstm_model_file': 'lstm_attack_model.h5',
                    'q_table_file': 'q_table.npy',
                    'tokenizer_file': 'tokenizer.json',
                    'max_sequence_length': '20'
                }
                config['user_accounts'] = {'test': 'test'}

        if args.user_account:
            if 'user_accounts' not in config:
                config['user_accounts'] = {}
            for account in args.user_account:
                if '=' in account:
                    key, value = account.split('=', 1)
                    config['user_accounts'][key.strip()] = value.strip()
                else:
                    config['user_accounts'][account.strip()] = ''

        _ = get_user_accounts(config)
    
        # Set up logging in UTC with JSON formatting.
        logging.Formatter.formatTime = lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(
            record.created, datetime.timezone.utc).isoformat(sep="T", timespec="milliseconds")
        sensor_name = config['honeypot'].get('sensor_name', socket.gethostname())
        global logger
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        log_file_handler = logging.FileHandler(config['honeypot'].get("log_file", "ssh_log.log"))
        log_file_handler.setFormatter(JSONFormatter(sensor_name))
        logger.addHandler(log_file_handler)
        logger.addFilter(ContextFilter())
    
        # Load ML models.
        global global_lstm_model, global_Q_table, global_tokenizer, global_max_seq_length
        global_lstm_model, global_Q_table, global_tokenizer, global_max_seq_length = load_ml_models(config)
    
        # Start the SSH honeypot server and the admin monitor task.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.create_task(start_server(config, global_tokenizer, global_lstm_model, global_Q_table, global_max_seq_length))
        loop.create_task(monitor_admin())
        loop.run_forever()
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
