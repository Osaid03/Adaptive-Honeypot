# honeypot_server/command_classifier.py
import os
import json
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import csv

# ✅ Define dataset directory & model files
DATASET_DIR = "model_assets"
LSTM_MODEL_FILE = os.path.join(DATASET_DIR, "lstm_attack_model.h5")
Q_TABLE_FILE = os.path.join(DATASET_DIR, "q_table.npy")
TOKENIZER_FILE = os.path.join(DATASET_DIR, "tokenizer.json")
ATTACK_DATA_FILE = os.path.join(DATASET_DIR, "attack_data.csv")
MAX_SEQUENCE_LENGTH = 20

# ✅ Load the pre-trained LSTM model
if not os.path.exists(LSTM_MODEL_FILE):
    raise FileNotFoundError(f"❌ LSTM model file '{LSTM_MODEL_FILE}' not found!")
lstm_model = tf.keras.models.load_model(LSTM_MODEL_FILE)

# ✅ Load Q-learning table
if not os.path.exists(Q_TABLE_FILE):
    raise FileNotFoundError(f"❌ Q-table file '{Q_TABLE_FILE}' not found!")
Q_table = np.load(Q_TABLE_FILE)

# ✅ Load Tokenizer properly
if not os.path.exists(TOKENIZER_FILE):
    raise FileNotFoundError(f"❌ Tokenizer file '{TOKENIZER_FILE}' not found!")
with open(TOKENIZER_FILE, 'r') as f:
    tokenizer_data = json.load(f)
    tokenizer_json_str = json.dumps(tokenizer_data)  # Convert to JSON string
    tokenizer = tf.keras.preprocessing.text.tokenizer_from_json(tokenizer_json_str)

# ✅ Load labeled commands from attack_data.csv
labeled_commands = {}
if os.path.exists(ATTACK_DATA_FILE):
    try:
        with open(ATTACK_DATA_FILE, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'command' in row and 'label' in row:
                    labeled_commands[row['command']] = row['label']
        print(f"✅ Loaded {len(labeled_commands)} labeled commands from {ATTACK_DATA_FILE}")
    except Exception as e:
        print(f"❌ Error loading attack data: {str(e)}")

def analyze_command(command):
    """
    ✅ Analyze a command using the LSTM model.
    ✅ Classify and detect anomaly based on tokenization behavior.
    Returns:
        prediction: Softmax probability output from LSTM
        is_anomaly: Boolean indicating anomaly (True = unknown command pattern)
    """
    if not command:
        return None, False

    # 🔹 First check if this command is in our labeled dataset
    if command in labeled_commands:
        print(f"✅ Command '{command}' found in labeled dataset with label: {labeled_commands[command]}")
        # Create a prediction that will result in the correct classification
        label = labeled_commands[command]
        if label == "BENIGN":
            prediction = np.array([[0.9, 0.05, 0.05]])
        elif label == "SUSPICIOUS":
            prediction = np.array([[0.05, 0.9, 0.05]])
        elif label == "MALICIOUS":
            prediction = np.array([[0.05, 0.05, 0.9]])
        else:
            prediction = None
        return prediction, False  # Not an anomaly since we have a label for it

    # 🔹 Tokenize
    sequences = tokenizer.texts_to_sequences([command])

    # 🔹 Check if sequence is empty or mostly unknown
    if not sequences or not sequences[0]:
        print(f"⚠️ Warning: Empty or unrecognized command: '{command}'")
        return None, True  # Treat fully unrecognized as anomaly

    token_ids = sequences[0]
    num_tokens = len(token_ids)
    num_unknown = token_ids.count(1)  # 1 = 'OOV' token in Keras by default

    # 🔎 If more than half tokens are unknown or total unknown > threshold
    is_anomaly = (num_unknown / num_tokens) > 0.5 or num_unknown > 3

    # 🔹 Pad
    padded_sequence = pad_sequences([token_ids], maxlen=MAX_SEQUENCE_LENGTH)

    # 🔹 Predict
    prediction = lstm_model.predict(padded_sequence)

    # 🔎 Debug Info
    print(f"🧠 LSTM Prediction: {prediction}")
    print(f"🔍 Command: {command}")
    print(f"📦 Tokens: {token_ids}")
    print(f"❓ Unknown Tokens: {num_unknown}/{num_tokens} → Anomaly: {is_anomaly}")

    return prediction, is_anomaly

def classify_command(prediction):
    """
    ✅ Classifies an SSH command based on the highest softmax probability.
    ✅ Returns one of: "BENIGN", "SUSPICIOUS", or "MALICIOUS".
    """
    if prediction is None:
        return "ANOMALOUS"

    outcomes = ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    idx = int(np.argmax(prediction))  # ✅ Pick the class with the highest probability
    classification = outcomes[idx]

    # ✅ Debugging Output
    print(f"DEBUG: Classification Index: {idx} → {classification}")

    return classification