
Adaptive Honeypot with AI-Powered Detection and Web Dashboard
==============================================================

This project is an advanced AI-powered SSH Honeypot system designed to attract, monitor, and analyze attacker behavior. It includes a machine learning-based command classifier, an AI-based fake Linux environment generator, and a real-time Flask dashboard to visualize incoming connections, commands, and session statistics.

Project Overview
----------------

The honeypot mimics a real SSH server and logs all activity. It uses:
- **LSTM Neural Network**: To analyze and classify each SSH command as Benign, Suspicious, or Malicious.
- **LangChain + OpenAI GPT**: To simulate a highly realistic Linux terminal environment.
- **Flask Web Dashboard**: To stream real-time logs, export data, and visualize attacker interactions.

Features
--------

✅ Realistic AI-powered Linux environment  
✅ Command classification using pre-trained LSTM  
✅ Real-time streaming of logs via Server-Sent Events  
✅ GeoIP lookup of attacker IPs  
✅ Export logs as CSV/JSON  
✅ Dockerized for easy deployment  
✅ Configurable via `config/config.ini`  

How to Run (Docker)
-------------------

1. **Build the Docker image:**

    ```bash
    docker build -t adaptive-honeypot .
    ```

2. **Create a `.env` file** in your project root:

    ```
    OPENAI_API_KEY=your_openai_key_here
    ```

3. **Run the app using Docker:**

    ```bash
    docker run -it --rm       --env-file .env       -p 8022:8022 -p 5000:5000       adaptive-honeypot
    ```

4. **Access the web dashboard:**
    - Visit `http://localhost:5000`

How to Run (Manual)
-------------------

1. Create and activate virtual environment:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Set your OpenAI key:

    ```bash
    export OPENAI_API_KEY=your_openai_key_here
    ```

4. Run the SSH honeypot:

    ```bash
    python3 -m honeypot_server.honeypot_runtime
    ```

5. In a separate terminal, run the web dashboard:

    ```bash
    python3 app.py
    ```

Configuration File
------------------

The honeypot behavior is configured via `config/config.ini`. Important sections:

```ini
[honeypot]
log_file = logs/ssh_log.log
sensor_name = my_honeypot

[ssh]
port = 8022
host_priv_key = ssh_host_key

[ml]
lstm_model_file = lstm_attack_model.h5
q_table_file = q_table.npy
tokenizer_file = tokenizer.json

[llm]
llm_provider = openai
model_name = gpt-4o

[user_accounts]
admin = admin123
* = *
```

Tech Stack
----------

- Python 3.11
- Flask
- AsyncSSH
- TensorFlow (LSTM model)
- LangChain + OpenAI (LLM simulation)
- Docker

Security Notes
--------------

- This is a **research and monitoring** tool. It does not block attackers, only logs and classifies them.
- Do **not** expose your honeypot on the open internet without proper safeguards.
- Consider integrating fail2ban, firewall rules, or external logging for production setups.

Author
------

Made by **Osaid Qattan**  
Graduation Project: *Advanced AI-Powered Intrusion Detection System for Dynamic Threat Protection*

License
-------

This project is licensed for educational and research use.

---

**Happy Hunting! 🕵️‍♂️🔥**
