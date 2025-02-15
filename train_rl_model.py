import numpy as np
import random

# Define state-action space
states = ["low_risk", "medium_risk", "high_risk"]
actions = ["delay_response", "fake_vulnerability", "terminate_connection"]
Q_table = np.zeros((len(states), len(actions)))

alpha = 0.1  # Learning rate
gamma = 0.9  # Discount factor
epsilon = 0.1  # Exploration rate

def get_state(event):
    if "rm -rf" in event or "wget" in event:
        return 2  # High risk
    elif "ls" in event or "pwd" in event:
        return 0  # Low risk
    else:
        return 1  # Medium risk

def choose_action(state):
    return random.randint(0, len(actions) - 1) if random.uniform(0, 1) < epsilon else np.argmax(Q_table[state])

def update_q_table(state, action, reward, next_state):
    best_next_action = np.argmax(Q_table[next_state])
    Q_table[state, action] = (1 - alpha) * Q_table[state, action] + alpha * (reward + gamma * Q_table[next_state, best_next_action])

if __name__ == "__main__":
    print("Reinforcement Learning Model Ready")
