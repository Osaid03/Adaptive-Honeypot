import json
import datetime
import logging
import os

DATASET_DIR = "datasets"
LOG_FILE = os.path.join(DATASET_DIR, "ssh_honeypot_logs.json")

logging.basicConfig(
    filename=LOG_FILE,  # Updated filename to match your dataset
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)

def log_event(event_type, **kwargs):
    """
    Logs events with a timestamp and additional provided information.
    The output is JSON formatted for easier downstream parsing.
    """
    log_entry = {
        "timestamp": str(datetime.datetime.utcnow()),
        "event": event_type
    }
    log_entry.update(kwargs)
    logger.info(json.dumps(log_entry))
