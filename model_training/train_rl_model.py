#!/usr/bin/env python3
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import os
import json

# ✅ Ensure TensorFlow uses the GPU efficiently
gpus = tf.config.experimental.list_physical_devices('GPU')
if gpus:
    try:
        tf.config.experimental.set_memory_growth(gpus[0], True)
        print(f"🚀 Using GPU: {gpus[0]}")
    except RuntimeError as e:
        print(e)

# ✅ Define dataset directory and file paths
DATASET_DIR = "datasets"
DATA_FILE = os.path.join(DATASET_DIR, "attack_data.csv")
Q_TABLE_FILE = os.path.join(DATASET_DIR, "q_table.npy")
MODEL_FILE = os.path.join(DATASET_DIR, "lstm_attack_model.h5")
TOKENIZER_FILE = os.path.join(DATASET_DIR, "tokenizer.json")
MAX_SEQUENCE_LENGTH = 20

# ✅ Load dataset
df = pd.read_csv(DATA_FILE)

# ✅ Q-learning hyperparameters
NUM_STATES = 100  # Fixed state limit (avoid index out of bounds)
NUM_ACTIONS = 3   # BENIGN (0), SUSPICIOUS (1), MALICIOUS (2)
ALPHA = 0.1       # Learning rate
GAMMA = 0.9       # Discount factor
EPSILON = 0.01    # Small noise to avoid state overfitting

# ✅ Define reward mapping
reward_mapping = {
    0: -1.0,  # BENIGN → Slight penalty to encourage finding attacks
    1: 0.3,   # SUSPICIOUS → Increased reward to make it distinct
    2: 2.0    # MALICIOUS → Strongest reward (highest priority)
}


# ✅ Convert labels to integer format
label_mapping = {"BENIGN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
df["label_int"] = df["label"].map(label_mapping)

# ✅ Initialize Q-table
Q_table = np.zeros((NUM_STATES, NUM_ACTIONS))

# ✅ Load trained LSTM model
if not os.path.exists(MODEL_FILE):
    raise FileNotFoundError(f"❌ LSTM model file '{MODEL_FILE}' not found!")
lstm_model = tf.keras.models.load_model(MODEL_FILE)

# ✅ Load tokenizer properly
if not os.path.exists(TOKENIZER_FILE):
    raise FileNotFoundError(f"❌ Tokenizer file '{TOKENIZER_FILE}' not found!")
with open(TOKENIZER_FILE, 'r') as f:
    tokenizer_data = json.load(f)
    tokenizer_json_str = json.dumps(tokenizer_data)  # Convert to JSON string
    tokenizer = tf.keras.preprocessing.text.tokenizer_from_json(tokenizer_json_str)

def analyze_command_batch(commands):
    """
    Tokenizes and processes a batch of commands using the trained LSTM model.
    Returns softmax probability predictions.
    """
    sequences = tokenizer.texts_to_sequences(commands)
    padded_sequences = pad_sequences(sequences, maxlen=MAX_SEQUENCE_LENGTH)
    predictions = lstm_model.predict(padded_sequences, verbose=0)
    return predictions

def determine_state(prediction):
    """
    Maps softmax probabilities to a Q-learning state (0-99).
    Uses all three class probabilities to generate a more balanced state representation.
    """
    benign, suspicious, malicious = prediction
    state = int((malicious * 80) + (suspicious * 40) - (benign * 20))  # Adjust scaling

    # ✅ Ensure state is within valid bounds (0 to 99)
    state = max(0, min(NUM_STATES - 1, state))
    return state

# ✅ Batch size for faster processing
BATCH_SIZE = 1024

# ✅ Training loop for Q-table
for start_idx in range(0, len(df), BATCH_SIZE):
    end_idx = min(start_idx + BATCH_SIZE, len(df))
    batch_df = df.iloc[start_idx:end_idx]
    commands = batch_df["command"].tolist()
    
    # ✅ Get LSTM predictions
    predictions = analyze_command_batch(commands)
    
    for idx, prediction in enumerate(predictions):
        command = batch_df.iloc[idx]["command"]
        label_int = batch_df.iloc[idx]["label_int"]
        
        state = determine_state(prediction)
        action = label_int
        reward = reward_mapping.get(action, 0)

        # ✅ Update Q-table with learning rate & discount factor
        current_value = Q_table[state, action]
        best_future = np.max(Q_table[state])  # Best future reward estimate
        Q_table[state, action] = (1 - ALPHA) * current_value + ALPHA * (reward + GAMMA * best_future + EPSILON)

        # ✅ Debug unexpected cases
        if state >= NUM_STATES:
            print(f"⚠️ Warning: State {state} out of bounds for command '{command}'. Adjusting to {NUM_STATES - 1}")

    print(f"✅ Processed rows {start_idx + 1} to {end_idx}/{len(df)}")

# ✅ Save the trained Q-table
np.save(Q_TABLE_FILE, Q_table)
print(f"✅ Q-table trained and saved to '{Q_TABLE_FILE}'")
