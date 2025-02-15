import pandas as pd
import tensorflow as tf
import numpy as np
from sklearn.metrics import classification_report

DATA_PATH = "processed_dataset.csv"
MODEL_PATH = "lstm_attack_model.h5"

def evaluate_model():
    df = pd.read_csv(DATA_PATH)
    model = tf.keras.models.load_model(MODEL_PATH)

    commands = df['command'].astype(str).tolist()
    unique_cmds = list(set(commands))
    cmd_to_index = {cmd: i for i, cmd in enumerate(unique_cmds)}

    X_test, y_test = [], []
    seq_length = 5
    for i in range(len(commands) - seq_length):
        X_test.append([cmd_to_index[cmd] for cmd in commands[i:i+seq_length]])
        y_test.append(cmd_to_index[commands[i+seq_length]])

    X_test = np.array(X_test).reshape(len(X_test), seq_length, 1)
    y_test = np.array(y_test)

    y_pred = np.argmax(model.predict(X_test), axis=1)

    print(classification_report(y_test, y_pred, target_names=unique_cmds))

if __name__ == "__main__":
    evaluate_model()
