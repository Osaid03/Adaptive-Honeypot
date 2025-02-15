import pandas as pd

DATASET_PATH = "../datasets/sample_dataset.csv"
OUTPUT_CSV = "processed_dataset.csv"

def preprocess_dataset():
    df = pd.read_csv(DATASET_PATH)

    # Assuming dataset contains 'timestamp', 'src_ip', 'event', 'command'
    df = df[['timestamp', 'src_ip', 'event', 'command']]
    
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Processed dataset saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    preprocess_dataset()
