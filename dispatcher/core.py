import json
import logging
import os
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime
from queue import Empty, Queue

import meshtastic
import pytz
from meshtastic.protobuf import config_pb2
from meshtastic.serial_interface import SerialInterface
from pubsub import pub
from tzlocal import get_localzone_name

import gb_db
import settings

# --- CONSTANTS ---
EXTREME_FORECAST_FLAGS = [
    ("tornado", "\U0001F32A\ufe0f"), ("blizzard", "\U0001F328\ufe0f"), ("whiteout", "\U0001F328\ufe0f"), ("hurricane", "\U0001F300"),
    ("heat index", "\U0001F525"), ("scorching", "\U0001F525"), ("cold", "\u2744\ufe0f"), ("frigid", "\U0001F976"),
    ("wind chill", "\U0001F976"), ("snow", "\u2744\ufe0f"), ("storm", "\u26c8\ufe0f"), ("thunderstorm", "\u26c8\ufe0f"),
    ("wind", "\U0001F32C\ufe0f"), ("fog", "\U0001F32B\ufe0f"), ("hail", "\U0001F328\ufe0f"), ("ice", "\U0001F9CA"), ("freeze", "\U0001F9CA"),
    ("flood", "\U0001F30A"), ("lightning", "\u26a1"), ("smoke", "\U0001F32B\ufe0f"), ("dust", "\U0001F32A\ufe0f"), ("drizzle", "\U0001F327\ufe0f")
]
NWS_ALERT_EMOJIS = [
    ("heat", "\U0001F525"), ("hot", "\U0001F525"), ("tornado", "\U0001F32A\ufe0f"), ("flood", "\U0001F30A"), ("thunderstorm", "\u26c8\ufe0f"),
    ("winter", "\u2744\ufe0f"), ("snow", "\u2744\ufe0f"), ("blizzard", "\u2744\ufe0f"), ("ice", "\U0001F9CA"), ("freeze", "\U0001F9CA"),
    ("wind", "\U0001F32C\ufe0f"), ("fog", "\U0001F32B\ufe0f"), ("air quality", "\U0001F637"), ("smoke", "\U0001F32B\ufe0f"), ("dust", "\U0001F32C\ufe0f"),
    ("special weather statement", "\u26a0\ufe0f"),
]
PREFIX_WEATHER = "\u2601\ufe0f"
PREFIX_FORECAST = "\U0001f52e"
PREFIX_ALERT = "\u26a1"
PREFIX_BOT_RESPONSE = "\U0001f916"
PREFIX_SCHEDULED = "\U0001F4C5"
PREFIX_EMAIL = "\U0001F4E7"
PREFIX_SOS = "\U0001F6A8"

BOT_MESSAGE_PREFIXES = (
    PREFIX_WEATHER, PREFIX_FORECAST, PREFIX_ALERT,
    PREFIX_BOT_RESPONSE, PREFIX_SCHEDULED, PREFIX_EMAIL, PREFIX_SOS
)

MAX_LOG_ENTRIES = 200
COMMAND_COOLDOWN_SECONDS = max(0.0, float(getattr(settings, "COMMAND_COOLDOWN_SECONDS", 1.0)))
COMMAND_BURST_LIMIT = getattr(settings, "COMMAND_BURST_LIMIT", 8)
COMMAND_BURST_WINDOW_SECONDS = getattr(settings, "COMMAND_BURST_WINDOW_SECONDS", 30)
COMMAND_QUEUE_WAIT_WARN_MS = max(1, int(getattr(settings, "COMMAND_QUEUE_WAIT_WARN_MS", 1500)))
COMMAND_HANDLER_WARN_MS = max(1, int(getattr(settings, "COMMAND_HANDLER_WARN_MS", 2500)))
SEND_QUEUE_WAIT_WARN_MS = max(1, int(getattr(settings, "SEND_QUEUE_WAIT_WARN_MS", 3000)))
SEND_EXEC_WARN_MS = max(1, int(getattr(settings, "SEND_EXEC_WARN_MS", 2000)))
SOS_COMMANDS = ("SOSP", "SOSF", "SOSM", "SOS")
CLEAR_COMMANDS = {"CLEAR", "CANCEL", "SAFE"}
ACK_COMMANDS = {"ACK"}
RESPONDING_COMMANDS = {"RESPONDING"}
CHECKIN_RESPONSES = {"Y", "YES", "OK"}


# --- GLOBAL VARIABLES & SETUP ---
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, "INFO"), format="%(asctime)s [%(levelname)s] %(message)s")
local_tz = pytz.timezone(get_localzone_name())
iface = None
subscribers = {}
subscribers_lock = threading.Lock()
subscribers_mtime = None
dispatcher_state_lock = threading.Lock()
dispatcher_state = {}
log_lock = threading.Lock()
dm_queue_lock = threading.Lock()
node_last_heard_cache = {}
CHANNEL0_LOG_FILE = getattr(settings, "CHANNEL0_LOG_FILE", "/opt/GuardianBridge/data/channel0_log.json")
node_last_heard_cache_lock = threading.Lock()
node_statuses_lock = threading.Lock()
user_last_command_time_lock = threading.Lock()
gateway_node_id = None
user_last_command_time = {}
user_command_history_lock = threading.Lock()
user_command_history = {}
user_interaction_state = {}
user_interaction_state_lock = threading.Lock()
broadcasted_alert_headlines = set()
broadcasted_alert_lock = threading.Lock()
sos_log_lock = threading.Lock()
process_start_ts = int(time.time())
runtime_error_lock = threading.Lock()
runtime_last_error = None

# --- Message Sending Queue ---
send_queue = Queue()
send_priority_queue = Queue()
command_queue = Queue()
MIN_SEND_INTERVAL_SECONDS = max(0.1, float(getattr(settings, "MIN_SEND_INTERVAL_SECONDS", 0.6)))
latency_metrics_lock = threading.Lock()
latency_metrics = {
    "command_queue_wait_ms": deque(maxlen=256),
    "command_handler_ms": deque(maxlen=256),
    "send_queue_wait_ms": deque(maxlen=256),
    "send_exec_ms": deque(maxlen=256),
}

# --- UTILITY FUNCTIONS ---
@contextmanager
def file_lock(lock_file_path):
    if os.path.exists(lock_file_path):
        logging.warning(f"Lock file {lock_file_path} already exists. Waiting...")

    retry_count = 0
    while retry_count < 10:
        try:
            fd = os.open(lock_file_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            time.sleep(0.1)
            retry_count += 1
    else:
        raise TimeoutError(f"Could not acquire lock for {lock_file_path} after 1 second.")

    try:
        yield
    finally:
        if os.path.exists(lock_file_path):
            os.remove(lock_file_path)


def save_json_locked(path, data):
    if path == settings.SUBSCRIBERS_FILE:
        gb_db.replace_subscribers(data)
        return
    lock_path = path + ".lock"
    with file_lock(lock_path):
        save_json(path, data)


def reload_subscribers(force=False):
    global subscribers, subscribers_mtime
    latest_mtime = gb_db.get_subscribers_mtime()
    if not force and subscribers_mtime is not None and latest_mtime == subscribers_mtime:
        logging.debug(f"Subscribers reload skipped (mtime unchanged: {latest_mtime}).")
        return False

    with subscribers_lock:
        previous_count = len(subscribers)
        new_subscribers_data = gb_db.load_subscribers_dict() or {}
        subscribers.clear()
        subscribers.update(new_subscribers_data)
        subscribers_mtime = latest_mtime
        current_count = len(subscribers)
        if current_count != previous_count:
            logging.info(f"Subscribers reloaded successfully. Total: {current_count}.")
        else:
            logging.debug(f"Subscribers reload completed. Total unchanged: {current_count}.")
        return True


def load_json(path):
    if not os.path.exists(path):
        return None
    for _ in range(3):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            time.sleep(0.05)
            continue
        except Exception as e:
            logging.error(f"Error loading JSON from {path}: {e}")
            return None
    logging.error(f"Error loading JSON from {path}: invalid JSON after retries")
    return None


def save_json(path, data):
    try:
        temp_filepath = path + ".tmp"
        with open(temp_filepath, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(temp_filepath, path)
    except Exception as e:
        logging.error(f"Error saving JSON to {path}: {e}")


def enqueue_command(sender, text, enqueued_at=None):
    queued_at = float(enqueued_at if enqueued_at is not None else time.time())
    command_queue.put((sender, text, queued_at))


def dequeue_send_job(idle_timeout_seconds=0.25):
    while True:
        try:
            return send_priority_queue.get_nowait()
        except Empty:
            pass
        try:
            return send_queue.get(timeout=max(0.05, float(idle_timeout_seconds)))
        except Empty:
            continue


def record_latency_sample(metric_name, value_ms):
    try:
        sample = float(value_ms)
    except (TypeError, ValueError):
        return
    if sample < 0:
        return
    with latency_metrics_lock:
        bucket = latency_metrics.get(metric_name)
        if bucket is not None:
            bucket.append(sample)


def _summarize_latency(samples):
    count = len(samples)
    if count <= 0:
        return {"count": 0, "avg_ms": None, "p95_ms": None, "max_ms": None}
    ordered = sorted(samples)
    p95_index = max(0, min(count - 1, int((count - 1) * 0.95)))
    avg_ms = sum(ordered) / count
    return {
        "count": count,
        "avg_ms": round(avg_ms, 1),
        "p95_ms": round(ordered[p95_index], 1),
        "max_ms": round(ordered[-1], 1),
    }


def get_latency_metric_snapshots():
    with latency_metrics_lock:
        snapshots = {name: list(values) for name, values in latency_metrics.items()}
    return {name: _summarize_latency(values) for name, values in snapshots.items()}


def get_formatted_timestamp():
    return datetime.now(local_tz).strftime("%H:%M %m/%d")


def get_log_timestamp():
    return datetime.now(local_tz).strftime("%H:%M %m/%d")


def log_channel_message(sender_id, text, is_dm=False):
    with log_lock:
        new_entry = {
            "from": sender_id,
            "timestamp": get_log_timestamp(),
            "text": text,
            "is_dm": is_dm,
        }
        gb_db.append_chat_log(new_entry, max_entries=MAX_LOG_ENTRIES)
        logging.debug(f"Logged message from {sender_id} (DM: {is_dm})")


def update_node_statuses(now=None):
    global node_last_heard_cache, gateway_node_id, node_last_heard_cache_lock
    if not iface:
        return

    with node_statuses_lock:
        existing_statuses = gb_db.load_node_statuses_dict() or {}

        known_node_ids = set(iface.nodes.keys())
        with node_last_heard_cache_lock:
            known_node_ids.update(set(node_last_heard_cache.keys()))

        desired_statuses = {}
        for node_id in known_node_ids:
            if node_id == gateway_node_id:
                continue

            node = iface.nodes.get(node_id)

            existing_node_data = existing_statuses.get(node_id, {})
            current_sos_status = existing_node_data.get("sos")
            current_active_tag = existing_node_data.get("active_tag_channel")
            last_known_lat = existing_node_data.get("latitude")
            last_known_lon = existing_node_data.get("longitude")

            if node:
                role_name = config_pb2.Config.DeviceConfig.Role.Name(node.get("role", 0))
                snr, hops_away, lib_last_heard = node.get("snr"), node.get("hopsAway"), node.get("lastHeard")
                lat, lon = node.get("latitude"), node.get("longitude")
            else:
                role_name, snr, hops_away, lib_last_heard, lat, lon = "UNKNOWN", None, None, None, None, None

            with node_last_heard_cache_lock:
                last_heard_ts = node_last_heard_cache.get(node_id, lib_last_heard)

            node_status = {
                "role": role_name,
                "lastHeard": last_heard_ts,
                "snr": snr,
                "hopsAway": hops_away,
                "latitude": lat if lat is not None else last_known_lat,
                "longitude": lon if lon is not None else last_known_lon,
            }
            if current_sos_status:
                node_status["sos"] = current_sos_status
            if current_active_tag:
                node_status["active_tag_channel"] = current_active_tag
            desired_statuses[node_id] = node_status

        if gateway_node_id and gateway_node_id in iface.nodes:
            my_node = iface.nodes[gateway_node_id]
            my_role_int = my_node.get("role", 0)
            my_role_name = config_pb2.Config.DeviceConfig.Role.Name(my_role_int)
            existing_gateway = existing_statuses.get(gateway_node_id, {})
            gateway_last_heard = existing_gateway.get("lastHeard")
            if not isinstance(gateway_last_heard, (int, float)):
                gateway_last_heard = time.time()
            desired_statuses[gateway_node_id] = {
                "role": my_role_name,
                "lastHeard": gateway_last_heard,
                "snr": "N/A",
                "hopsAway": 0,
                "latitude": my_node.get("latitude"),
                "longitude": my_node.get("longitude"),
            }

        desired_ids = set(desired_statuses.keys())
        existing_ids = set(existing_statuses.keys())
        upsert_count = 0
        for node_id, status in desired_statuses.items():
            if existing_statuses.get(node_id) != status:
                gb_db.upsert_node_status(node_id, status)
                upsert_count += 1

        delete_count = 0
        for stale_node_id in (existing_ids - desired_ids):
            gb_db.delete_node_status(stale_node_id)
            delete_count += 1

        logging.debug(
            f"Updated node statuses: total={len(desired_statuses)} upserted={upsert_count} deleted={delete_count}."
        )


def update_dispatcher_status(now=None):
    def _safe_file_size(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    def _safe_qsize(queue_obj):
        try:
            return int(queue_obj.qsize())
        except Exception:
            return 0

    db_size = _safe_file_size(settings.DB_PATH)
    wal_size = _safe_file_size(settings.DB_PATH + "-wal")
    shm_size = _safe_file_size(settings.DB_PATH + "-shm")
    command_job_backlog_count = gb_db.count_command_jobs(statuses=("queued", "running"))
    command_job_oldest_age = gb_db.oldest_command_job_age(statuses=("queued", "running"))
    command_backlog_count = command_job_backlog_count
    oldest_command_age = command_job_oldest_age
    send_queue_depth = _safe_qsize(send_queue)
    send_priority_queue_depth = _safe_qsize(send_priority_queue)
    command_queue_depth = _safe_qsize(command_queue)
    dead_letter_count = gb_db.count_command_dead_letters()
    latency = get_latency_metric_snapshots()
    command_wait_stats = latency.get("command_queue_wait_ms", {})
    command_handler_stats = latency.get("command_handler_ms", {})
    send_wait_stats = latency.get("send_queue_wait_ms", {})
    send_exec_stats = latency.get("send_exec_ms", {})
    subscribers_count = gb_db.count_subscribers()
    active_sos_count = gb_db.count_active_sos_logs()

    dispatcher_state_age = None
    if os.path.exists(settings.DISPATCHER_STATE_FILE):
        try:
            dispatcher_state_age = int(time.time() - os.path.getmtime(settings.DISPATCHER_STATE_FILE))
        except OSError:
            dispatcher_state_age = None

    with runtime_error_lock:
        last_error = dict(runtime_last_error) if isinstance(runtime_last_error, dict) else None

    alerts = []
    if iface is None:
        alerts.append(
            {
                "level": "critical",
                "code": "radio_disconnected",
                "message": "Meshtastic radio interface is disconnected.",
            }
        )
    if command_backlog_count >= 100:
        alerts.append(
            {
                "level": "critical",
                "code": "command_backlog_high",
                "message": f"Command backlog is high ({command_backlog_count} items).",
            }
        )
    elif command_backlog_count >= 20:
        alerts.append(
            {
                "level": "warn",
                "code": "command_backlog_elevated",
                "message": f"Command backlog elevated ({command_backlog_count} items).",
            }
        )
    if oldest_command_age is not None and oldest_command_age >= 300:
        alerts.append(
            {
                "level": "warn",
                "code": "command_backlog_oldest_stale",
                "message": f"Oldest queued command age is {oldest_command_age}s.",
            }
        )
    if dead_letter_count > 0:
        alerts.append(
            {
                "level": "warn",
                "code": "command_dead_letters_present",
                "message": f"{dead_letter_count} command(s) are in dead-letter state.",
            }
        )
    if send_queue_depth >= 60:
        alerts.append(
            {
                "level": "warn",
                "code": "send_queue_depth_high",
                "message": f"Send queue depth is {send_queue_depth}.",
            }
        )
    if send_priority_queue_depth >= 20:
        alerts.append(
            {
                "level": "warn",
                "code": "send_priority_queue_depth_high",
                "message": f"Priority send queue depth is {send_priority_queue_depth}.",
            }
        )
    if command_queue_depth >= 60:
        alerts.append(
            {
                "level": "warn",
                "code": "command_queue_depth_high",
                "message": f"Command worker queue depth is {command_queue_depth}.",
            }
        )
    if (command_wait_stats.get("p95_ms") or 0) >= COMMAND_QUEUE_WAIT_WARN_MS:
        alerts.append(
            {
                "level": "warn",
                "code": "command_queue_wait_high",
                "message": f"Command queue wait p95 is {command_wait_stats.get('p95_ms')}ms.",
            }
        )
    if (command_handler_stats.get("p95_ms") or 0) >= COMMAND_HANDLER_WARN_MS:
        alerts.append(
            {
                "level": "warn",
                "code": "command_handler_slow",
                "message": f"Command handler p95 is {command_handler_stats.get('p95_ms')}ms.",
            }
        )
    if (send_wait_stats.get("p95_ms") or 0) >= SEND_QUEUE_WAIT_WARN_MS:
        alerts.append(
            {
                "level": "warn",
                "code": "send_queue_wait_high",
                "message": f"Send queue wait p95 is {send_wait_stats.get('p95_ms')}ms.",
            }
        )
    if (send_exec_stats.get("p95_ms") or 0) >= SEND_EXEC_WARN_MS:
        alerts.append(
            {
                "level": "warn",
                "code": "send_exec_slow",
                "message": f"Send execution p95 is {send_exec_stats.get('p95_ms')}ms.",
            }
        )
    if isinstance(last_error, dict):
        last_error_msg = str(last_error.get("message") or "").strip()
        if last_error_msg:
            alerts.append(
                {
                    "level": "warn",
                    "code": "runtime_last_error",
                    "message": last_error_msg[:240],
                }
            )

    status_data = {
        "radio_connected": (iface is not None),
        "last_update": datetime.now(local_tz).isoformat(),
        "runtime": {
            "process_start_ts": process_start_ts,
            "last_error": last_error,
        },
        "alerts": alerts,
        "metrics": {
            "db_size_bytes": db_size,
            "db_wal_bytes": wal_size,
            "db_shm_bytes": shm_size,
            "db_total_bytes": db_size + wal_size + shm_size,
            "outgoing_email_queue": gb_db.count_outgoing_emails(),
            "failed_dm_queue": gb_db.count_failed_dm_queue(),
            "subscribers_count": subscribers_count,
            "active_sos_count": active_sos_count,
            "dispatcher_state_age_seconds": dispatcher_state_age,
            "command_backlog_count": command_backlog_count,
            "command_oldest_age_seconds": oldest_command_age,
            "command_job_backlog_count": command_job_backlog_count,
            "command_job_oldest_age_seconds": command_job_oldest_age,
            "send_queue_depth": send_queue_depth,
            "send_priority_queue_depth": send_priority_queue_depth,
            "command_queue_depth": command_queue_depth,
            "command_dead_letter_count": dead_letter_count,
            "command_queue_wait_ms": command_wait_stats,
            "command_handler_ms": command_handler_stats,
            "send_queue_wait_ms": send_wait_stats,
            "send_exec_ms": send_exec_stats,
        },
    }
    save_json(settings.DISPATCHER_STATUS_FILE, status_data)


def record_runtime_error(source: str, message: str) -> None:
    source_clean = str(source or "").strip() or "unknown"
    message_clean = str(message or "").strip() or "unknown error"
    with runtime_error_lock:
        global runtime_last_error
        runtime_last_error = {
            "timestamp": datetime.now(local_tz).isoformat(),
            "source": source_clean,
            "message": message_clean,
        }


def run_auto_db_backup(now=None):
    interval_hours = max(0, int(getattr(settings, "AUTO_BACKUP_INTERVAL_HOURS", 6)))
    if interval_hours <= 0:
        logging.debug("Automatic DB backups are disabled (AUTO_BACKUP_INTERVAL_HOURS <= 0).")
        return

    base_dir = getattr(settings, "BASE_DIR", "/opt/GuardianBridge")
    output_dir = getattr(settings, "AUTO_BACKUP_DIR", os.path.join(base_dir, "AutoBackUp"))
    os.makedirs(output_dir, exist_ok=True)
    backup_path = gb_db.create_db_backup(output_dir)
    logging.info(f"Automatic DB backup completed. DB backup: {backup_path}")


def run_periodic_task(target_func, interval_seconds, name):
    if interval_seconds <= 0:
        logging.error(f"Invalid interval for periodic task '{name}': {interval_seconds}. Task will not start.")
        return
    logging.info(f"Starting periodic task '{name}' with interval of {interval_seconds} seconds.")
    while True:
        try:
            now = datetime.now(local_tz)
            target_func(now)
        except Exception as e:
            logging.error(f"Error in periodic task '{name}': {e}", exc_info=True)
            record_runtime_error(f"periodic:{name}", str(e))

        time.sleep(interval_seconds - (time.time() % interval_seconds))


def main():
    global iface, subscribers, dispatcher_state, gateway_node_id, broadcasted_alert_headlines
    from .commands import command_processor_worker, handle_temp_group_expiry, process_command_jobs
    from .messaging import broadcast_to_subscribers, on_meshtastic_message, sender_thread_worker
    from .sos import handle_active_sos_tasks
    from .weather import (
        get_alert_emoji,
        handle_custom_broadcasts,
        handle_daily_forecasts,
        handle_nws_alert_broadcasts,
        handle_periodic_weather_broadcasts,
    )

    try:
        gb_db.ensure_db()
        iface = SerialInterface()
        logging.info("Waiting for Meshtastic interface to initialize...")
        time.sleep(2)
        node_num_int = iface.myInfo.my_node_num
        gateway_node_id = f"!{node_num_int:08x}"
        logging.info(f"Dispatcher started. Gateway Node ID: {gateway_node_id}")
    except Exception as e:
        logging.critical(f"Failed to connect to Meshtastic device: {e}", exc_info=True)
        record_runtime_error("startup:meshtastic_connect", str(e))
        update_dispatcher_status()
        exit(1)

    pub.subscribe(on_meshtastic_message, "meshtastic.receive")

    reload_subscribers(force=True)
    dispatcher_state = load_json(settings.DISPATCHER_STATE_FILE) or {}

    logging.info("Performing initial broadcast of active NWS alerts...")
    initial_alerts = load_json(settings.WEATHER_ALERTS_FILE) or []
    initial_headlines = {alert.get("headline") for alert in initial_alerts if alert.get("headline")}
    if initial_headlines:
        for headline in initial_headlines:
            broadcast_to_subscribers(f"{get_alert_emoji(headline)} {headline}", "alerts")
        with broadcasted_alert_lock:
            broadcasted_alert_headlines.update(initial_headlines)
        logging.info(f"Broadcasted and initialized with {len(broadcasted_alert_headlines)} known alerts.")
    else:
        logging.info("No active NWS alerts found on startup.")

    now = datetime.now(local_tz)
    logging.info("Performing initial broadcast of weather conditions...")
    handle_periodic_weather_broadcasts(now, initial_broadcast=True)
    logging.info("Initial broadcasts complete. Starting main loop.")

    sender_thread = threading.Thread(target=sender_thread_worker, daemon=True)
    sender_thread.start()

    command_processor_thread = threading.Thread(target=command_processor_worker, daemon=True)
    command_processor_thread.start()

    auto_backup_interval_seconds = max(0, int(getattr(settings, "AUTO_BACKUP_INTERVAL_HOURS", 6))) * 3600
    command_job_poll_seconds = max(0.1, float(getattr(settings, "COMMAND_JOB_POLL_SECONDS", 0.5)))
    command_job_batch_size = max(1, int(getattr(settings, "COMMAND_JOB_BATCH_SIZE", 20)))
    tasks = [
        threading.Thread(
            target=run_periodic_task,
            args=(lambda now: process_command_jobs(max_jobs=command_job_batch_size), command_job_poll_seconds, "process_command_jobs"),
            daemon=True,
        ),
        threading.Thread(target=run_periodic_task, args=(update_node_statuses, 30, "update_node_statuses"), daemon=True),
        threading.Thread(target=run_periodic_task, args=(lambda now: reload_subscribers(force=False), 30, "reload_subscribers"), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_temp_group_expiry, 3600, "handle_temp_group_expiry"), daemon=True),
        threading.Thread(
            target=run_periodic_task,
            args=(
                lambda now: gb_db.prune_command_receipts(
                    ttl_hours=max(1, int(getattr(settings, "COMMAND_RECEIPT_TTL_HOURS", 72))),
                    now_ts=int(now.timestamp()),
                ),
                3600,
                "prune_command_receipts",
            ),
            daemon=True,
        ),
        threading.Thread(
            target=run_periodic_task,
            args=(
                lambda now: gb_db.prune_command_jobs(
                    retention_hours=max(1, int(getattr(settings, "COMMAND_JOB_RETENTION_HOURS", 168))),
                    now_ts=int(now.timestamp()),
                ),
                3600,
                "prune_command_jobs",
            ),
            daemon=True,
        ),
        threading.Thread(target=run_periodic_task, args=(handle_active_sos_tasks, 60, "handle_active_sos_tasks"), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_nws_alert_broadcasts, 60, "handle_nws_alert_broadcasts"), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_periodic_weather_broadcasts, 60, "handle_periodic_weather_broadcasts"), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_daily_forecasts, 60, "handle_daily_forecasts"), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_custom_broadcasts, 60, "handle_custom_broadcasts"), daemon=True),
        threading.Thread(target=run_periodic_task, args=(update_dispatcher_status, 30, "update_dispatcher_status"), daemon=True),
    ]
    if auto_backup_interval_seconds > 0:
        tasks.append(
            threading.Thread(
                target=run_periodic_task,
                args=(run_auto_db_backup, auto_backup_interval_seconds, "run_auto_db_backup"),
                daemon=True,
            )
        )

    for task in tasks:
        task.start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt detected. Shutting down...")
    finally:
        enqueue_command(None, None)
        send_priority_queue.put(None)
        send_queue.put(None)
        iface_ref = iface
        iface = None
        update_dispatcher_status()
        if iface_ref:
            iface_ref.close()


class Dispatcher:
    """Main dispatcher entrypoint."""

    def run(self):
        main()
