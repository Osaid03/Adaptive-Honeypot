# Use an official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy all project files
COPY . .

# Install system dependencies (optional)
RUN apt-get update && apt-get install -y \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expose SSH port (if needed)
EXPOSE 8022
EXPOSE 5000

# Default command to run your honeypot
CMD ["bash", "-c", "python3 -m honeypot_server.honeypot_runtime & exec python3 app.py"]
