#!/usr/bin/env python3
import json
import pandas as pd
import os

# Define dataset directory
DATASET_DIR = "datasets"
LOG_FILE = os.path.join(DATASET_DIR, "honeypot_logs.json")
OUTPUT_CSV = os.path.join(DATASET_DIR, "attack_data.csv")

commands = []
labels = []

with open(LOG_FILE, "r") as f:
    logs = json.load(f)
    for log in logs:
        if log.get("event") == "Session summary":
            command_text = log.get("details", "")
            judgement = log.get("judgement", "UNKNOWN")
            commands.append(command_text)
            labels.append(judgement)

df = pd.DataFrame({"command": commands, "label": labels})
df.to_csv(OUTPUT_CSV, index=False)
print(f"✅ Processed {len(df)} attack entries and saved as '{OUTPUT_CSV}'")
