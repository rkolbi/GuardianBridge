# GuardianBridge Settings
#
# This file contains configuration parameters for the GuardianBridge application.
# It loads settings from environment variables, typically defined in a .env file,
# and provides default values where environment variables are not set.
#
# For more information on GuardianBridge, please refer to the project documentation.
#
# Copyright (C) 2025 Robert Kolbasowski
# License: GNU General Public License v3.0 or later (see LICENSE file for details)

# settings.py

import os
from dotenv import load_dotenv

# Load environment variables from .env file
# This allows for flexible configuration without modifying the code directly.
load_dotenv()

# --- Core Application Settings ---
# Geographic coordinates for the GuardianBridge's location.
# Used for location-based services like weather fetching and map tile downloads.
LATITUDE = float(os.getenv("LATITUDE", 30.0000))
LONGITUDE = float(os.getenv("LONGITUDE", -90.0000))
# Logging level for the application (e.g., "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# --- Meshtastic Interface Settings ---
# Serial port where the Meshtastic device is connected (e.g., "/dev/ttyUSB0" on Linux).
# If not set, the Meshtastic library will attempt to auto-detect.
MESHTASTIC_PORT = os.getenv("MESHTASTIC_PORT", None)

# --- Email Gateway Configuration ---
# Email address used by GuardianBridge for sending and receiving messages.
EMAIL_USER = os.getenv("EMAIL_USER", "")
# Password for the EMAIL_USER account.
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
# IMAP server address for incoming emails (e.g., "imap.gmail.com").
IMAP_SERVER = os.getenv("IMAP_SERVER", "")
# IMAP server port (default is 993 for SSL/TLS).
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
# Name of the IMAP folder where processed emails are moved.
TRASH_FOLDER_NAME = os.getenv("TRASH_FOLDER_NAME", "Trash")
# Maximum length of an email body that will be processed or sent over Meshtastic.
MAX_EMAIL_BODY_LEN = int(os.getenv("MAX_EMAIL_BODY_LEN", 200))

# --- Data File Paths ---
# Base directory for all GuardianBridge data files.
DATA_DIR = "/opt/GuardianBridge/data"
# Path to the JSON file storing Meshtastic node status information.
NODE_STATUS_FILE = os.path.join(DATA_DIR, "node_status.json")
# Path to the JSON file storing subscriber information (e.g., email, preferences).
SUBSCRIBERS_FILE = os.path.join(DATA_DIR, "subscribers.json")
# Directory for storing incoming command files from email or other sources.
COMMANDS_DIR = os.path.join(DATA_DIR, "commands")
# Path to the JSON file for queuing outgoing emails.
OUTGOING_EMAIL_FILE = os.path.join(DATA_DIR, "outgoing_emails.json")
# Path to the JSON file storing current weather conditions.
WEATHER_CURRENT_FILE = os.path.join(DATA_DIR, "weather_current.json")
# Path to the JSON file storing weather forecast data.
WEATHER_FORECAST_FILE = os.path.join(DATA_DIR, "weather_forecast.json")
# Path to the JSON file storing active NWS weather alerts.
WEATHER_ALERTS_FILE = os.path.join(DATA_DIR, "nws_alerts.json")
# Path to the JSON file storing the dispatcher's operational state.
DISPATCHER_STATE_FILE = os.path.join(DATA_DIR, "dispatcher_state.json")
# Path to the JSON file storing the dispatcher's current status.
DISPATCHER_STATUS_FILE = os.path.join(DATA_DIR, "dispatcher_status.json")
# Path to the JSON file defining scheduled dispatcher jobs (e.g., custom broadcasts).
DISPATCHER_JOBS_FILE = os.path.join(DATA_DIR, "dispatcher_jobs.json")
# Path to a timestamp file indicating the last successful run of the weather fetcher.
WEATHER_FETCHER_LASTRUN_FILE = os.path.join(DATA_DIR, "weather_fetcher.lastrun")
# Path to a timestamp file indicating the last successful run of the email processor.
EMAIL_PROCESSOR_LASTRUN_FILE = os.path.join(DATA_DIR, "email_processor.lastrun")
# Path to the JSON file for queuing failed direct messages for retry.
FAILED_DM_QUEUE_FILE = os.path.join(DATA_DIR, "failed_dm_queue.json")
# Path to the JSON file for logging SOS events.
SOS_LOG_FILE = os.path.join(DATA_DIR, "sos_log.json") 
# Path to a text file containing instructions for SOS email notifications.
SOS_EMAIL_INSTRUCTIONS_FILE = os.path.join(DATA_DIR, "sos_email_instructions.txt")

# --- Scheduled Broadcast Intervals ---
# Frequency (in minutes) for broadcasting NWS weather alerts.
WEATHER_ALERT_INTERVAL_MINS = int(os.getenv("WEATHER_ALERT_INTERVAL_MINS", 15))
# Frequency (in minutes) for broadcasting current weather conditions.
WEATHER_UPDATE_INTERVAL_MINS = int(os.getenv("WEATHER_UPDATE_INTERVAL_MINS", 30))

# --- Daily Forecast Broadcast Times ---
# Times of day (HH:MM) when daily weather forecasts are broadcast.
# These values are read from environment variables and can be configured.
morning_time = os.getenv("FORECAST_MORNING_SEND_TIME", "07:00").strip()
afternoon_time = os.getenv("FORECAST_AFTERNOON_SEND_TIME", "19:00").strip()

# A list of valid forecast send times, filtering out any empty entries.
FORECAST_SEND_TIMES = [t for t in [morning_time, afternoon_time] if t]


# --- HTTP Request Configuration (for weather_fetcher.py) ---
# User-Agent string for HTTP requests to external APIs (e.g., weather.gov).
USER_AGENT = "MeshtasticGateway/1.0"
# Total number of retries for failed HTTP requests.
HTTP_RETRY_TOTAL = 3
# Backoff factor for retrying HTTP requests (e.g., 2 means 1s, 2s, 4s delays).
HTTP_RETRY_BACKOFF = 2

# --- SOS Notification Settings ---
# Boolean flags to enable/disable email notifications for different SOS types.
SOS_EMAIL_ENABLED = os.getenv("SOS_EMAIL_ENABLED", 'False').lower() in ('true', '1', 't')
SOSM_EMAIL_ENABLED = os.getenv("SOSM_EMAIL_ENABLED", 'False').lower() in ('true', '1', 't')
SOSF_EMAIL_ENABLED = os.getenv("SOSF_EMAIL_ENABLED", 'False').lower() in ('true', '1', 't')
SOSP_EMAIL_ENABLED = os.getenv("SOSP_EMAIL_ENABLED", 'False').lower() in ('true', '1', 't')
# Lists of email addresses to receive notifications for different SOS types.
SOS_EMAIL_RECIPIENTS = [email.strip() for email in os.getenv("SOS_EMAIL_RECIPIENTS", "").split(',') if email.strip()]
SOSM_EMAIL_RECIPIENTS = [email.strip() for email in os.getenv("SOSM_EMAIL_RECIPIENTS", "").split(',') if email.strip()]
SOSF_EMAIL_RECIPIENTS = [email.strip() for email in os.getenv("SOSF_EMAIL_RECIPIENTS", "").split(',') if email.strip()]
SOSP_EMAIL_RECIPIENTS = [email.strip() for email in os.getenv("SOSP_EMAIL_RECIPIENTS", "").split(',') if email.strip()]

# --- SOS Escalation Timers ---
# Time (in minutes) before an unacknowledged SOS alert escalates.
SOS_ACK_TIMEOUT_MINS = int(os.getenv("SOS_ACK_TIMEOUT_MINS", 5))
# Interval (in minutes) for sending check-in pings to active SOS users.
SOS_CHECKIN_INTERVAL_MINS = int(os.getenv("SOS_CHECKIN_INTERVAL_MINS", 5))
# Maximum number of failed check-in attempts before an SOS user is marked as unresponsive.
SOS_CHECKIN_MAX_ATTEMPTS = int(os.getenv("SOS_CHECKIN_MAX_ATTEMPTS", 3))
