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

def _getenv_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = str(raw).strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default

def _getenv_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = str(raw).strip()
    if raw == "":
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default

# --- Core Application Settings ---
# Geographic coordinates for the GuardianBridge's location.
# Used for location-based services like weather fetching and map tile downloads.
LATITUDE = _getenv_float("LATITUDE", 30.0000)
LONGITUDE = _getenv_float("LONGITUDE", -90.0000)
# Logging level for the application (e.g., "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
# Human-readable server identity used in mesh command responses and UI context.
SERVER_NAME = (os.getenv("SERVER_NAME", "GuardianBridge") or "GuardianBridge").strip()
# Server software version string used in mesh command responses.
SERVER_VERSION = (os.getenv("SERVER_VERSION", "v1.4.0") or "v1.4.0").strip()

# --- Meshtastic Interface Settings ---
# Serial port where the Meshtastic device is connected (e.g., "/dev/ttyUSB0" on Linux).
# If not set, the Meshtastic library will attempt to auto-detect.
MESHTASTIC_PORT = os.getenv("MESHTASTIC_PORT", None)
# Max bytes for a single Meshtastic text message payload (conservative default).
MAX_MESH_TEXT_LEN = _getenv_int("MAX_MESH_TEXT_LEN", 180)

# --- Email Gateway Configuration ---
# Email address used by GuardianBridge for sending and receiving messages.
EMAIL_USER = os.getenv("EMAIL_USER", "")
# Password for the EMAIL_USER account.
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
# IMAP server address for incoming emails (e.g., "imap.gmail.com").
IMAP_SERVER = os.getenv("IMAP_SERVER", "")
# IMAP server port (default is 993 for SSL/TLS).
IMAP_PORT = _getenv_int("IMAP_PORT", 993)
# SMTP server address for outgoing emails (e.g., "smtp.gmail.com").
SMTP_SERVER = os.getenv("SMTP_SERVER", IMAP_SERVER)
# SMTP server port (default is 587 for STARTTLS).
SMTP_PORT = _getenv_int("SMTP_PORT", 587)
# Name of the IMAP folder where processed emails are moved.
TRASH_FOLDER_NAME = os.getenv("TRASH_FOLDER_NAME", "Trash")
# Maximum length of an email body that will be processed or sent over Meshtastic.
MAX_EMAIL_BODY_LEN = _getenv_int("MAX_EMAIL_BODY_LEN", 200)

# --- Data File Paths ---
# Base directory for all GuardianBridge data files.
BASE_DIR = "/opt/GuardianBridge"
DATA_DIR = os.path.join(BASE_DIR, "data")
# SQLite database file for high-traffic data (subscribers, node status, logs).
DB_PATH = os.path.join(DATA_DIR, "guardianbridge.db")
# Directory for automatic scheduled DB backups.
AUTO_BACKUP_DIR = os.path.join(BASE_DIR, "AutoBackUp")
# JSON cache path used by APIs and diagnostics.
NODE_STATUS_FILE = os.path.join(DATA_DIR, "node_status.json")
# Subscriber updates are persisted in SQLite (this path is kept for lock/file utility calls).
SUBSCRIBERS_FILE = os.path.join(DATA_DIR, "subscribers.json")
# Legacy lock-path retained for email processor file-lock semantics.
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
# JSON cache/compatibility path used by tests and tooling.
DISPATCHER_JOBS_FILE = os.path.join(DATA_DIR, "dispatcher_jobs.json")
# Path to a timestamp file indicating the last successful run of the weather fetcher.
WEATHER_FETCHER_LASTRUN_FILE = os.path.join(DATA_DIR, "weather_fetcher.lastrun")
# Path to a timestamp file indicating the last successful run of the email processor.
EMAIL_PROCESSOR_LASTRUN_FILE = os.path.join(DATA_DIR, "email_processor.lastrun")
# JSON cache/compatibility path used by tests and tooling.
FAILED_DM_QUEUE_FILE = os.path.join(DATA_DIR, "failed_dm_queue.json")
# JSON cache/compatibility path used by tests and tooling.
SOS_LOG_FILE = os.path.join(DATA_DIR, "sos_log.json") 
# Path to a text file containing instructions for SOS email notifications.
SOS_EMAIL_INSTRUCTIONS_FILE = os.path.join(DATA_DIR, "sos_email_instructions.txt")
EMAIL_BLOCKLIST_FILE = os.path.join(DATA_DIR, 'email_blocklist.json')

# --- Scheduled Broadcast Intervals ---
# Frequency (in minutes) for broadcasting NWS weather alerts.
WEATHER_ALERT_INTERVAL_MINS = _getenv_int("WEATHER_ALERT_INTERVAL_MINS", 15)
# Frequency (in minutes) for broadcasting current weather conditions.
WEATHER_UPDATE_INTERVAL_MINS = _getenv_int("WEATHER_UPDATE_INTERVAL_MINS", 30)
# Max age (in minutes) for weather observations before they are treated as stale.
WEATHER_DATA_MAX_AGE_MINUTES = _getenv_int("WEATHER_DATA_MAX_AGE_MINUTES", 120)
# Minutes before a node is considered stale in the UI.
STALE_NODE_MINUTES = _getenv_int("STALE_NODE_MINUTES", 120)

# --- Rate Limiting ---
# Maximum number of commands allowed per sender within a rolling window (0 disables burst limiting).
COMMAND_BURST_LIMIT = _getenv_int("COMMAND_BURST_LIMIT", 8)
# Window size in seconds for command burst limiting.
COMMAND_BURST_WINDOW_SECONDS = _getenv_int("COMMAND_BURST_WINDOW_SECONDS", 30)
# Minimum seconds between accepted commands from the same sender (0 disables cooldown).
COMMAND_COOLDOWN_SECONDS = max(0.0, _getenv_float("COMMAND_COOLDOWN_SECONDS", 1.0))
# Minimum spacing between outbound mesh sends to reduce radio congestion.
MIN_SEND_INTERVAL_SECONDS = max(0.1, _getenv_float("MIN_SEND_INTERVAL_SECONDS", 0.6))
# Warn threshold (milliseconds) for command queue wait time (enqueue -> dequeue).
COMMAND_QUEUE_WAIT_WARN_MS = _getenv_int("COMMAND_QUEUE_WAIT_WARN_MS", 1500)
# Warn threshold (milliseconds) for command handler execution time.
COMMAND_HANDLER_WARN_MS = _getenv_int("COMMAND_HANDLER_WARN_MS", 2500)
# Warn threshold (milliseconds) for send queue wait time (enqueue -> dequeue).
SEND_QUEUE_WAIT_WARN_MS = _getenv_int("SEND_QUEUE_WAIT_WARN_MS", 3000)
# Warn threshold (milliseconds) for radio send execution time.
SEND_EXEC_WARN_MS = _getenv_int("SEND_EXEC_WARN_MS", 2000)
# Retention for processed command receipts used for idempotency.
COMMAND_RECEIPT_TTL_HOURS = _getenv_int("COMMAND_RECEIPT_TTL_HOURS", 72)
# Maximum delivery attempts for queued command jobs before dead-lettering.
COMMAND_JOB_MAX_ATTEMPTS = _getenv_int("COMMAND_JOB_MAX_ATTEMPTS", 5)
# Maximum seconds a worker can hold a claimed command job lease before it can be reclaimed.
COMMAND_JOB_LEASE_SECONDS = _getenv_int("COMMAND_JOB_LEASE_SECONDS", 30)
# Base retry delay (seconds) for failed command jobs.
COMMAND_JOB_RETRY_BASE_SECONDS = _getenv_int("COMMAND_JOB_RETRY_BASE_SECONDS", 2)
# Maximum retry delay (seconds) for failed command jobs.
COMMAND_JOB_RETRY_MAX_SECONDS = _getenv_int("COMMAND_JOB_RETRY_MAX_SECONDS", 300)
# Number of queued command jobs processed per scheduler tick.
COMMAND_JOB_BATCH_SIZE = _getenv_int("COMMAND_JOB_BATCH_SIZE", 20)
# Poll interval (seconds) for command job processing.
COMMAND_JOB_POLL_SECONDS = max(0.1, _getenv_float("COMMAND_JOB_POLL_SECONDS", 0.5))
# Retention for completed/failed command jobs.
COMMAND_JOB_RETENTION_HOURS = _getenv_int("COMMAND_JOB_RETENTION_HOURS", 168)
# Maximum number of incoming emails allowed per sender within a rolling window (0 disables email rate limiting).
EMAIL_RATE_LIMIT_MAX = _getenv_int("EMAIL_RATE_LIMIT_MAX", 6)
# Window size in seconds for email rate limiting.
EMAIL_RATE_LIMIT_WINDOW_SECONDS = _getenv_int("EMAIL_RATE_LIMIT_WINDOW_SECONDS", 300)
# Persistent state for email rate limiting.
EMAIL_RATE_LIMIT_FILE = os.path.join(DATA_DIR, "email_rate_limit.json")
# Max rows to retain in the outgoing email quarantine table.
OUTGOING_EMAIL_QUARANTINE_MAX = _getenv_int("OUTGOING_EMAIL_QUARANTINE_MAX", 500)

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
SOS_ACK_TIMEOUT_MINS = _getenv_int("SOS_ACK_TIMEOUT_MINS", 5)
# Interval (in minutes) for sending check-in pings to active SOS users.
SOS_CHECKIN_INTERVAL_MINS = _getenv_int("SOS_CHECKIN_INTERVAL_MINS", 5)
# Maximum number of failed check-in attempts before an SOS user is marked as unresponsive.
SOS_CHECKIN_MAX_ATTEMPTS = _getenv_int("SOS_CHECKIN_MAX_ATTEMPTS", 3)
# Temporary group inactivity timeout (days) before auto-expiry.
TEMP_GROUP_TTL_DAYS = _getenv_int("TEMP_GROUP_TTL_DAYS", 14)
# Automatic DB backup interval in hours (0 disables periodic backups).
AUTO_BACKUP_INTERVAL_HOURS = _getenv_int("AUTO_BACKUP_INTERVAL_HOURS", 6)
