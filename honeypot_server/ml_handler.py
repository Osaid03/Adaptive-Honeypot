# honeypot_server/ml_handler.py
import os
import json
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences

# ✅ Define dataset directory & model files
DATASET_DIR = "datasets"
LSTM_MODEL_FILE = os.path.join(DATASET_DIR, "lstm_attack_model.h5")
Q_TABLE_FILE = os.path.join(DATASET_DIR, "q_table.npy")
TOKENIZER_FILE = os.path.join(DATASET_DIR, "tokenizer.json")
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

def analyze_command(command):
    """
    ✅ Analyzes a single SSH command using the LSTM model.
    ✅ Returns the raw softmax prediction probabilities.
    """
    if not command:
        return None

    sequences = tokenizer.texts_to_sequences([command])
    if not sequences or not sequences[0]:  
        print(f"⚠️ Warning: Unrecognized command '{command}'")
        return None  

    padded_sequence = pad_sequences(sequences, maxlen=MAX_SEQUENCE_LENGTH)
    prediction = lstm_model.predict(padded_sequence)
    
    # ✅ Debugging Output
    print(f"DEBUG: Softmax Probabilities for '{command}': {prediction}")

    return prediction

def classify_command(prediction):
    """
    ✅ Classifies an SSH command based on the highest softmax probability.
    ✅ Returns one of: "BENIGN", "SUSPICIOUS", or "MALICIOUS".
    """
    if prediction is None:
        return "UNKNOWN"

    outcomes = ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    idx = int(np.argmax(prediction))  # ✅ Pick the class with the highest probability
    classification = outcomes[idx]

    # ✅ Debugging Output
    print(f"DEBUG: Classification Index: {idx} → {classification}")

    return classification
