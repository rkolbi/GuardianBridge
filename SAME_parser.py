#!/usr/bin/env python3
import sys
import json
from datetime import datetime, timezone


# --- Configuration ---
OUTPUT_FILE = "/opt/GuardianBridge/data/SAME_messages.json"
# --- End Configuration ---

def parse_same_message(message):
    """Parses a raw SAME message string and returns a dictionary."""
    parts = message.strip().split('-')
    parsed_data = {}
    try:
        parsed_data['originator'] = parts[1]
        parsed_data['event_code'] = parts[2]
        # Further parsing for location, time, etc. can be added here
        # For now, we'll keep it simple as multimon-ng's output can vary.
    except IndexError:
        # Not a full message, return an empty dict
        pass
    return parsed_data

def append_to_json_log(filepath, data):
    """Reads a JSON file, appends new data, and writes it back."""
    try:
        with open(filepath, 'r+') as f:
            log_data = json.load(f) if f.read(1) else []
            log_data.append(data)
            f.seek(0)
            json.dump(log_data, f, indent=2)
            f.truncate()
    except (IOError, json.JSONDecodeError):
        with open(filepath, 'w') as f:
            json.dump([data], f, indent=2)

def main():
    """
    Reads from stdin, buffers a complete SAME message,
    parses it, and appends it to the JSON log file.
    """
    message_buffer = []
    in_message = False

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        # Look for the start of a message
        if "ZCZC" in line:
            in_message = True
            message_buffer = [line.split(':', 1)[-1].strip()] # Start with the clean message
            continue

        # If we are in a message, look for the end
        if in_message and "NNNN" in line:
            in_message = False
            raw_message = "".join(message_buffer)
            
            # Create the final JSON object
            json_output = {
                "received_utc": datetime.now(timezone.utc).isoformat(),
                "processed": False,
                "raw_message": raw_message
            }

            # Add parsed data to the object
            parsed_info = parse_same_message(raw_message)
            if parsed_info:
                json_output.update(parsed_info)

            append_to_json_log(OUTPUT_FILE, json_output)

            message_buffer = [] # Clear the buffer for the next message

        # If we are in a message, keep adding to it
        elif in_message:
            message_buffer.append(line)

if __name__ == "__main__":
    main()
