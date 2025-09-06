# GuardianBridge - A Meshtastic Gateway for Community Resilience
# Copyright (C) 2025 Robert Kolbasowski
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# settings.py

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Core Settings ---
LATITUDE = float(os.getenv("LATITUDE", 30.0000))
LONGITUDE = float(os.getenv("LONGITUDE", -90.0000))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# --- Meshtastic Settings ---
MESHTASTIC_PORT = os.getenv("MESHTASTIC_PORT", None)

# --- Email Gateway Settings ---
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
IMAP_SERVER = os.getenv("IMAP_SERVER", "")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
TRASH_FOLDER_NAME = os.getenv("TRASH_FOLDER_NAME", "Trash")
MAX_EMAIL_BODY_LEN = int(os.getenv("MAX_EMAIL_BODY_LEN", 200))

# --- File Paths ---
DATA_DIR = "/opt/GuardianBridge/data"
NODE_STATUS_FILE = os.path.join(DATA_DIR, "node_status.json")
SUBSCRIBERS_FILE = os.path.join(DATA_DIR, "subscribers.json")
COMMANDS_DIR = os.path.join(DATA_DIR, "commands")
OUTGOING_EMAIL_FILE = os.path.join(DATA_DIR, "outgoing_emails.json")
WEATHER_CURRENT_FILE = os.path.join(DATA_DIR, "weather_current.json")
WEATHER_FORECAST_FILE = os.path.join(DATA_DIR, "weather_forecast.txt")
WEATHER_ALERTS_FILE = os.path.join(DATA_DIR, "nws_alerts.txt")
DISPATCHER_STATE_FILE = os.path.join(DATA_DIR, "dispatcher_state.json")
DISPATCHER_STATUS_FILE = os.path.join(DATA_DIR, "dispatcher_status.json")
DISPATCHER_JOBS_FILE = os.path.join(DATA_DIR, "dispatcher.txt")
WEATHER_FETCHER_LASTRUN_FILE = os.path.join(DATA_DIR, "weather_fetcher.lastrun")
EMAIL_PROCESSOR_LASTRUN_FILE = os.path.join(DATA_DIR, "email_processor.lastrun")
FAILED_DM_QUEUE_FILE = os.path.join(DATA_DIR, "failed_dm_queue.json")
SOS_LOG_FILE = os.path.join(DATA_DIR, "sos_log.json") # New file for SOS logging

# --- Broadcast Interval Settings ---
WEATHER_ALERT_INTERVAL_MINS = int(os.getenv("WEATHER_ALERT_INTERVAL_MINS", 15))
WEATHER_UPDATE_INTERVAL_MINS = int(os.getenv("WEATHER_UPDATE_INTERVAL_MINS", 30))

# --- Broadcast Schedule Settings (FIXED) ---
# This section now correctly reads the schedule from your .env file,
# allowing the PHP admin page to modify it.
morning_time = os.getenv("FORECAST_MORNING_SEND_TIME", "07:00").strip()
afternoon_time = os.getenv("FORECAST_AFTERNOON_SEND_TIME", "19:00").strip()

# This list is dynamically built from the .env variables.
# It filters out any empty strings, so if you leave a variable blank
# in .env, it won't cause an error.
FORECAST_SEND_TIMES = [t for t in [morning_time, afternoon_time] if t]


# --- HTTP Request Settings for weather_fetcher.py ---
USER_AGENT = "MeshtasticGateway/1.0"
HTTP_RETRY_TOTAL = 3
HTTP_RETRY_BACKOFF = 2
