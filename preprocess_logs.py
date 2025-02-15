import pandas as pd
import json

LOG_FILE = "../cowrie/var/log/cowrie.json"
OUTPUT_CSV = "processed_logs.csv"

def process_cowrie_logs():
    data = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                data.append(log_entry)
            except json.JSONDecodeError:
                continue

    df = pd.DataFrame(data)

    # Keep only relevant columns
    df = df[['timestamp', 'src_ip', 'session', 'eventid', 'input']]
    
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Processed logs saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    process_cowrie_logs()
