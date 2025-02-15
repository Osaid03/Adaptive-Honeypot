import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
import pandas as pd
import numpy as np

DATA_PATH = "processed_dataset.csv"
MODEL_PATH = "lstm_attack_model.h5"

def load_data():
    df = pd.read_csv(DATA_PATH)
    commands = df['command'].astype(str).tolist()
    unique_cmds = list(set(commands))
    cmd_to_index = {cmd: i for i, cmd in enumerate(unique_cmds)}

    X, y = [], []
    seq_length = 5
    for i in range(len(commands) - seq_length):
        X.append([cmd_to_index[cmd] for cmd in commands[i:i+seq_length]])
        y.append(cmd_to_index[commands[i+seq_length]])

    X = np.array(X).reshape(len(X), seq_length, 1)
    y = np.array(y)

    return X, y, len(unique_cmds)

def train_model():
    X, y, num_classes = load_data()

    model = Sequential([
        LSTM(50, input_shape=(X.shape[1], 1), return_sequences=True),
        LSTM(50),
        Dense(num_classes, activation='softmax')
    ])

    model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(X, y, epochs=10, batch_size=32)

    model.save(MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
