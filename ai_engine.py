from tensorflow.keras.models import load_model
import numpy as np

MODEL_PATH = "lstm_attack_model.h5"

model = load_model(MODEL_PATH)

def predict_next_command(previous_cmds, cmd_to_index, unique_cmds):
    input_sequence = [cmd_to_index[cmd] for cmd in previous_cmds[-5:]]
    input_sequence = np.array(input_sequence).reshape(1, 5, 1)
    prediction = model.predict(input_sequence)
    return unique_cmds[np.argmax(prediction)]
