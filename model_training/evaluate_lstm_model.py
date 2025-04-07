#!/usr/bin/env python3
import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from tensorflow.keras.preprocessing.text import tokenizer_from_json
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import load_model

# === Config ===
DATA_FILE = "model_assets/attack_data.csv"
MODEL_FILE = "model_assets/lstm_attack_model.h5"
TOKENIZER_FILE = "model_assets/tokenizer.json"
MAX_SEQUENCE_LENGTH = 30

# === Load Data ===
df = pd.read_csv(DATA_FILE)
print("🔢 Dataset shape:", df.shape)
original_texts = df["command"].values  # ✅ Moved after loading df

# === Load Tokenizer ===
with open(TOKENIZER_FILE, "r") as f:
    tokenizer = tokenizer_from_json(f.read())

sequences = tokenizer.texts_to_sequences(df["command"])
X = pad_sequences(sequences, maxlen=MAX_SEQUENCE_LENGTH)

# === Labels ===
label_mapping = {"BENIGN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
reverse_label_map = {v: k for k, v in label_mapping.items()}
y = df["label"].map(label_mapping).values

# === Split Data ===
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

# === Load Trained Model ===
model = load_model(MODEL_FILE)

# === Predict ===
y_pred_probs = model.predict(X_test)
y_pred = np.argmax(y_pred_probs, axis=1)

# === Evaluation ===
print("📊 Classification Report:")
print(classification_report(y_test, y_pred, target_names=label_mapping.keys()))

# === Confusion Matrix ===
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=label_mapping.keys(), yticklabels=label_mapping.keys())
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig("confusion_matrix.png")
plt.show()

# === Misclassified Commands Logger ===
misclassified = []
for i in range(len(y_test)):
    true_label = y_test[i]
    predicted_label = y_pred[i]
    if true_label != predicted_label:
        misclassified.append({
            "command": original_texts[i],
            "true_label": reverse_label_map[true_label],
            "predicted_label": reverse_label_map[predicted_label]
        })

# Save misclassified to CSV
df_errors = pd.DataFrame(misclassified)
df_errors.to_csv("model_assets/misclassified_commands.csv", index=False)
print("❌ Misclassified commands saved to 'model_assets/misclassified_commands.csv'")