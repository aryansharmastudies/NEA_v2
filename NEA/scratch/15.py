from datetime import datetime
import uuid
import queue
import json
import os

sync_queue = queue.Queue()

if os.path.exists("events.json"):
    with open("events.json", "r") as f:
        for item in json.load(f):
            sync_queue.put(item)
    print(sync_queue)
else:
    print("No events.json file found. Starting with empty queue.")

def generate_event_id():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    uid = str(uuid.uuid4())[:6]
    return f"event_{timestamp}_{uid}"

# Create the event dictionary
event = {
    "id": generate_event_id(),
    "time_added": datetime.now().isoformat(),
    "event_type": "modified",
    "path": "/home/osaka/Desktop/Java/bruh.txt",
    "is_directory": False,
    "file_hash": "abc123...",
    "origin": "watchdog",
    "status": "pending",
    "retries": 0
}

# Add to queue
sync_queue.put(event)

all_events = list(sync_queue.queue)

with open("events.json", "w") as f:
    json.dump(all_events, f, indent=2)