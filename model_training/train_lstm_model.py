#!/usr/bin/env python3
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import os
import json

# Dataset paths
DATASET_DIR = "model_assets"
DATA_FILE = os.path.join(DATASET_DIR, "attack_data.csv")
MODEL_FILE = os.path.join(DATASET_DIR, "lstm_attack_model.h5")
TOKENIZER_FILE = os.path.join(DATASET_DIR, "tokenizer.json")

# Load dataset
df = pd.read_csv(DATA_FILE)
print("Dataset sample:", df.head())

# Tokenizer setup
tokenizer = Tokenizer(oov_token="<UNK>")  # Handle unseen words
tokenizer.fit_on_texts(df["command"])
sequences = tokenizer.texts_to_sequences(df["command"])

# Save tokenizer
with open(TOKENIZER_FILE, "w") as f:
    f.write(tokenizer.to_json())

# Define sequence length
MAX_SEQUENCE_LENGTH = 30
X = pad_sequences(sequences, maxlen=MAX_SEQUENCE_LENGTH)

# Label mapping
label_mapping = {"BENIGN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
y = df["label"].map(label_mapping).values

# Class weighting for imbalance handling
class_weight = {0: 1.0, 1: 2.0, 2: 3.0}

# Cross-validation setup
skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
best_accuracy = 0
best_model = None

# Training
for fold, (train_index, val_index) in enumerate(skf.split(X, y), 1):
    print(f"Training fold {fold}/3...")
    X_train, X_val = X[train_index], X[val_index]
    y_train, y_val = y[train_index], y[val_index]

    model = Sequential([
        Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=32, input_length=MAX_SEQUENCE_LENGTH),
        LSTM(128, return_sequences=True),
        BatchNormalization(),
        Dropout(0.6),
        LSTM(64),
        BatchNormalization(),
        Dropout(0.6),
        Dense(32, activation='relu'),
        Dense(3, activation='softmax')
    ])

    optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
    lr_scheduler = ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=2, verbose=1)

    model.compile(loss='sparse_categorical_crossentropy', optimizer=optimizer, metrics=['accuracy'])

    early_stopping = EarlyStopping(monitor='val_loss', patience=2, restore_best_weights=True)
    
    model.fit(X_train, y_train, epochs=10, batch_size=64, validation_data=(X_val, y_val),
              class_weight=class_weight, callbacks=[early_stopping, lr_scheduler])

    loss, accuracy = model.evaluate(X_val, y_val)
    print(f"Validation Accuracy (fold {fold}): {accuracy:.2f}")

    if accuracy > best_accuracy:
        best_accuracy = accuracy
        best_model = model

# Save best model
if best_model:
    best_model.save(MODEL_FILE)
    print(f"✅ Best model saved to '{MODEL_FILE}'")
