from flask import Flask, Response, render_template
import time

app = Flask(__name__)

# This function simulates "tailing" a log file. In a real scenario, you would
# read from your actual log file (e.g., ssh_log.log)
def generate_log_stream():
    with open("ssh_log.log", "r") as f:
        # Go to the end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                # Yield the line as an SSE message.
                yield f"data: {line}\n\n"
            else:
                time.sleep(1)

@app.route('/stream')
def stream():
    return Response(generate_log_stream(), mimetype="text/event-stream")

@app.route('/')
def index():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
