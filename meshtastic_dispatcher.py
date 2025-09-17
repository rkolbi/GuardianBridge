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

# meshtastic_dispatcher.py

import os
import json
import time
import logging
from datetime import datetime
from tzlocal import get_localzone_name
import pytz
import meshtastic
from meshtastic.protobuf import config_pb2
from meshtastic.serial_interface import SerialInterface
from pubsub import pub
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import settings
import threading
from queue import Queue
from contextlib import contextmanager

# --- CONSTANTS ---
EXTREME_FORECAST_FLAGS = [
    ("tornado", "🌪️"), ("blizzard", "🌨️"), ("whiteout", "🌨️"), ("hurricane", "🌀"),
    ("heat index", "🔥"), ("scorching", "🔥"), ("cold", "❄️"), ("frigid", "🥶"),
    ("wind chill", "🥶"), ("snow", "❄️"), ("storm", "⛈️"), ("thunderstorm", "⛈️"),
    ("wind", "🌬️"), ("fog", "🌫️"), ("hail", "🌨️"), ("ice", "🧊"), ("freeze", "🧊"),
    ("flood", "🌊"), ("lightning", "⚡"), ("smoke", "🌫️"), ("dust", "🌪️"), ("drizzle", "💧")
]
NWS_ALERT_EMOJIS = [
    ("heat", "🔥"), ("hot", "🔥"), ("tornado", "🌪️"), ("flood", "🌊"), ("thunderstorm", "⛈️"),
    ("winter", "❄️"), ("snow", "❄️"), ("blizzard", "❄️"), ("ice", "🧊"), ("freeze", "🧊"),
    ("wind", "🌬️"), ("fog", "🌫️"), ("air quality", "😷"), ("smoke", "🌫️"), ("dust", "🌬️"),
    ("special weather statement", "⚠️"),
]
PREFIX_WEATHER = "\u2601\ufe0f"
PREFIX_FORECAST = "\U0001f52e"
PREFIX_ALERT = "\u26a1"
PREFIX_BOT_RESPONSE = "\U0001f916"
PREFIX_SCHEDULED = "🗓️"
PREFIX_EMAIL = "📧"
PREFIX_SOS = "🆘"

BOT_MESSAGE_PREFIXES = (
    PREFIX_WEATHER, PREFIX_FORECAST, PREFIX_ALERT,
    PREFIX_BOT_RESPONSE, PREFIX_SCHEDULED, PREFIX_EMAIL, PREFIX_SOS
)

MAX_LOG_ENTRIES = 200
COMMAND_COOLDOWN_SECONDS = 3
SOS_COMMANDS = ("SOSP", "SOSF", "SOSM", "SOS")
CLEAR_COMMANDS = {"CLEAR", "CANCEL", "SAFE"}
ACK_COMMANDS = {"ACK"}
RESPONDING_COMMANDS = {"RESPONDING"}
CHECKIN_RESPONSES = {"Y", "YES", "OK"}


# --- GLOBAL VARIABLES & SETUP ---
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, 'INFO'), format="%(asctime)s [%(levelname)s] %(message)s")
local_tz = pytz.timezone(get_localzone_name())
iface = None
subscribers = {}
subscribers_lock = threading.Lock()
dispatcher_state_lock = threading.Lock()
dispatcher_state = {}
log_lock = threading.Lock()
dm_queue_lock = threading.Lock()
node_last_heard_cache = {}
CHANNEL0_LOG_FILE = getattr(settings, 'CHANNEL0_LOG_FILE', '/opt/GuardianBridge/data/channel0_log.json')
node_last_heard_cache_lock = threading.Lock()
user_last_command_time_lock = threading.Lock()
gateway_node_id = None
user_last_command_time = {}
user_interaction_state = {}
user_interaction_state_lock = threading.Lock()
broadcasted_alert_headlines = set()

# --- Message Sending Queue ---
send_queue = Queue()
command_queue = Queue()
MIN_SEND_INTERVAL_SECONDS = 1.1

# --- Watchdog event handler with debouncing ---
watchdog_event_lock = threading.Lock()
last_event_times = {}
DEBOUNCE_SECONDS = 2

# --- Watchdog event handler ---
class MasterFileEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        with watchdog_event_lock:
            if event.is_directory:
                return

            filepath = event.src_path
            now = time.time()

            if (now - last_event_times.get(filepath, 0)) < DEBOUNCE_SECONDS:
                return

            last_event_times[filepath] = now
            filename = os.path.basename(filepath)

            if filepath.startswith(settings.COMMANDS_DIR) and filename.endswith('.json'):
                logging.info(f"Watchdog event (COMMAND) for: {filename}")
                process_command_file(filepath)
            elif filename == os.path.basename(settings.SUBSCRIBERS_FILE):
                logging.info(f"Watchdog event (CONFIG) for: {filename}. Reloading subscribers...")
                reload_subscribers()
            elif filename == os.path.basename(settings.WEATHER_ALERTS_FILE):
                logging.info(f"Watchdog event (ALERT) for: {filename}. Checking for new alerts...")
                handle_new_alert_broadcast()


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
    lock_path = path + ".lock"
    with file_lock(lock_path):
        save_json(path, data)

def reload_subscribers():
    global subscribers
    with subscribers_lock:
        new_subscribers_data = load_json(settings.SUBSCRIBERS_FILE) or {}
        subscribers.clear()
        subscribers.update(new_subscribers_data)
        logging.info(f"Subscribers reloaded successfully. Total: {len(subscribers)}.")

def load_json(path):
    if not os.path.exists(path): return None
    try:
        with open(path, "r") as f: return json.load(f)
    except Exception as e:
        logging.error(f"Error loading JSON from {path}: {e}")
        return None

def save_json(path, data):
    try:
        temp_filepath = path + ".tmp"
        with open(temp_filepath, "w") as f: json.dump(data, f, indent=2)
        os.rename(temp_filepath, path)
    except Exception as e:
        logging.error(f"Error saving JSON to {path}: {e}")

def get_formatted_timestamp():
    return datetime.now(local_tz).strftime("%H:%M %m/%d")

def get_log_timestamp():
    return datetime.now(local_tz).strftime("%H:%M %m/%d")

def log_channel_message(sender_id, text, is_dm=False):
    with log_lock:
        log_data = load_json(CHANNEL0_LOG_FILE) or []
        new_entry = {
            "from": sender_id, 
            "timestamp": get_log_timestamp(), 
            "text": text, 
            "is_dm": is_dm
        }
        log_data.append(new_entry)
        if len(log_data) > MAX_LOG_ENTRIES:
            log_data = log_data[-MAX_LOG_ENTRIES:]
        save_json(CHANNEL0_LOG_FILE, log_data)
        logging.debug(f"Logged message from {sender_id} (DM: {is_dm})")

def send_meshtastic_message(text, **kwargs):
    kwargs['text'] = text
    send_queue.put(kwargs)

def sender_thread_worker():
    global node_last_heard_cache
    logging.info("Sender thread started.")
    while True:
        try:
            kwargs = send_queue.get()
            if kwargs is None:
                break

            start_time = time.time()
            
            text = kwargs.get("text")
            destination_id = kwargs.get("destinationId")
            text_for_log = kwargs.pop("text_for_log", text)
            
            log_channel_message("GATEWAY", text_for_log, is_dm=(destination_id is not None))

            if iface:
                try:
                    iface.sendText(**kwargs)
                    logging.info(f"Sent: '{text}' -> {destination_id or 'Broadcast'}")
                except meshtastic.MeshtasticException as e:
                    logging.warning(f"Failed to send message to {destination_id}: {e}. Queuing for retry.")
                    if destination_id:
                        with dm_queue_lock:
                            queue = load_json(settings.FAILED_DM_QUEUE_FILE) or []
                            queue.append({"destination_id": destination_id, "text": text, "timestamp": datetime.now(local_tz).isoformat()})
                            save_json(settings.FAILED_DM_QUEUE_FILE, queue)
                except Exception as e:
                    logging.error(f"Unexpected error sending message to {destination_id}: {e}", exc_info=True)

            elapsed = time.time() - start_time
            if elapsed < MIN_SEND_INTERVAL_SECONDS:
                time.sleep(MIN_SEND_INTERVAL_SECONDS - elapsed)

        except Exception as e:
            logging.error(f"Error in sender thread: {e}", exc_info=True)

def get_command_handler(text):
    text_upper = text.upper()
    
    sos_command = next((cmd for cmd in SOS_COMMANDS if text_upper.startswith(cmd)), None)
    if sos_command:
        return handle_sos_alert, (sos_command, text[len(sos_command):].strip())

    command_map = {
        **{cmd: (handle_sos_clear, ()) for cmd in CLEAR_COMMANDS},
        **{cmd: (handle_sos_action_initial, (text_upper,)) for cmd in ACK_COMMANDS.union(RESPONDING_COMMANDS)},
        **{cmd: (handle_sos_checkin_response, ()) for cmd in CHECKIN_RESPONSES}
    }
    
    command_word = text_upper.split()[0]
    if command_word in command_map:
        return command_map[command_word]

    return handle_meshtastic_command, (text,)

def command_processor_worker():
    logging.info("Command processor thread started.")
    while True:
        try:
            sender, text = command_queue.get()
            if sender is None:
                break

            current_time = time.time()
            with user_last_command_time_lock:
                if current_time - user_last_command_time.get(sender, 0) < COMMAND_COOLDOWN_SECONDS:
                    logging.warning(f"User {sender} rate-limited. Ignoring command: '{text}'")
                    continue
                user_last_command_time[sender] = current_time

            with user_interaction_state_lock:
                if user_interaction_state.get(sender) == "awaiting_sos_choice":
                    parts = text.upper().split()
                    cmd_word, cmd_arg = parts[0], parts[1] if len(parts) > 1 else None
                    if cmd_word in ACK_COMMANDS.union(RESPONDING_COMMANDS) and cmd_arg and cmd_arg.isdigit():
                        del user_interaction_state[sender]
                        handle_sos_choice(sender, cmd_word, int(cmd_arg))
                        continue
            
            handler, args = get_command_handler(text)
            handler(sender, *args)

        except Exception as e:
            logging.error(f"Error in command processor thread: {e}", exc_info=True)

def update_node_statuses(now=None):
    global node_last_heard_cache, gateway_node_id, node_last_heard_cache_lock
    if not iface: return

    node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
    
    known_node_ids = set(iface.nodes.keys())
    known_node_ids.update(node_last_heard_cache.keys())

    for node_id in known_node_ids:
        if node_id == gateway_node_id:
            continue
            
        node = iface.nodes.get(node_id)
        
        existing_node_data = node_statuses.get(node_id, {})
        current_sos_status = existing_node_data.get('sos')
        current_active_tag = existing_node_data.get('active_tag_channel')
        last_known_lat = existing_node_data.get('latitude')
        last_known_lon = existing_node_data.get('longitude')

        if node:
            role_name = config_pb2.Config.DeviceConfig.Role.Name(node.get('role', 0))
            snr, hops_away, lib_last_heard = node.get('snr'), node.get('hopsAway'), node.get('lastHeard')
            lat, lon = node.get('latitude'), node.get('longitude')
        else:
            role_name, snr, hops_away, lib_last_heard, lat, lon = "UNKNOWN", None, None, None, None, None
        
        with node_last_heard_cache_lock:
            last_heard_ts = node_last_heard_cache.get(node_id, lib_last_heard)
        
        node_statuses[node_id] = {
            "role": role_name, 
            "lastHeard": last_heard_ts, 
            "snr": snr, 
            "hopsAway": hops_away,
            "latitude": lat if lat is not None else last_known_lat,
            "longitude": lon if lon is not None else last_known_lon
        }
        if current_sos_status:
            node_statuses[node_id]['sos'] = current_sos_status
        if current_active_tag:
            node_statuses[node_id]['active_tag_channel'] = current_active_tag

    if gateway_node_id and gateway_node_id in iface.nodes:
        my_node = iface.nodes[gateway_node_id]
        my_role_int = my_node.get('role', 0)
        my_role_name = config_pb2.Config.DeviceConfig.Role.Name(my_role_int)
        node_statuses[gateway_node_id] = {
            "role": my_role_name,
            "lastHeard": time.time(),
            "snr": "N/A",
            "hopsAway": 0,
            "latitude": my_node.get('latitude'),
            "longitude": my_node.get('longitude')
        }
    
    save_json(settings.NODE_STATUS_FILE, node_statuses)
    logging.debug(f"Updated node status file for {len(node_statuses)} nodes.")

def update_sos_status(node_id, sos_code):
    node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
    if node_id not in node_statuses:
        node_statuses[node_id] = {}
    
    if sos_code:
        node_statuses[node_id]['sos'] = sos_code
        logging.info(f"Set SOS status for {node_id} to {sos_code}")
    elif 'sos' in node_statuses.get(node_id, {}):
        del node_statuses[node_id]['sos']
        logging.info(f"Cleared SOS status for {node_id}")

    save_json(settings.NODE_STATUS_FILE, node_statuses)

def broadcast_to_subscribers(message, subscription_key):
    with subscribers_lock:
        current_subscribers = list(subscribers.items())
    for sender_id, sub_data in current_subscribers:
        if sub_data.get(subscription_key, False) and not sub_data.get('blocked', False):
            send_meshtastic_message(message, destinationId=sender_id, wantAck=True)

def highlight_extreme_conditions(text):
    if not text: return ""
    text_lower = text.lower()
    flags = {emoji for keyword, emoji in EXTREME_FORECAST_FLAGS if keyword in text_lower}
    return " ".join(sorted(list(flags)))

def get_alert_emoji(headline):
    headline_lower = headline.lower()
    for keyword, emoji in NWS_ALERT_EMOJIS:
        if keyword in headline_lower: return emoji
    return PREFIX_ALERT

def _find_forecast_period(periods, now, is_daytime=None, target_date=None):
    target_date = target_date or now.date()
    for period in periods:
        try:
            start_time = datetime.fromisoformat(period.get("startTime", "").replace("Z", "+00:00"))
            if is_daytime is not None:
                if start_time.astimezone(local_tz).date() == target_date and period.get("isDaytime") == is_daytime:
                    return period
            else:
                end_time = datetime.fromisoformat(period.get("endTime", "").replace("Z", "+00:00"))
                if start_time <= now < end_time:
                    return period
        except (ValueError, KeyError): continue
    if is_daytime is None:
        for period in periods:
            try:
                start_time = datetime.fromisoformat(period.get("startTime", "").replace("Z", "+00:00"))
                if start_time >= now:
                    logging.info(f"No active forecast found. Falling back to next upcoming period: {period.get('name')}")
                    return period
            except (ValueError, KeyError): continue
    return None

def _create_forecast_message(period, on_demand=False):
    if not period: return "Not available"
    name = period.get('name', 'N/A')
    short_fc = period.get('shortForecast', 'N/A')
    temp = period.get('temperature', 'N/A')
    temp_unit = period.get('temperatureUnit', '')
    flags = highlight_extreme_conditions(short_fc)
    if on_demand:
        message = f"{name}: {short_fc}, {temp}°{temp_unit}"
    else:
        message = f"{short_fc}, {temp}°{temp_unit}"
    if flags: message += f" {flags}"
    return message

def get_current_forecast_message():
    forecast_data = load_json(settings.WEATHER_FORECAST_FILE)
    if not forecast_data or "periods" not in forecast_data:
        return "No forecast data available."
    now = datetime.now(local_tz)
    current_period = _find_forecast_period(forecast_data["periods"], now, is_daytime=None)
    if not current_period:
        return "Unable to retrieve current or upcoming forecast."
    return f"{PREFIX_FORECAST} {_create_forecast_message(current_period, on_demand=True)}"

def _has_time_elapsed(last_time_iso, now, interval_mins):
    if not last_time_iso: return True
    last_sent_time = datetime.fromisoformat(last_time_iso)
    return (now - last_sent_time).total_seconds() >= interval_mins * 60

def handle_new_alert_broadcast():
    global broadcasted_alert_headlines
    alerts_data = load_json(settings.WEATHER_ALERTS_FILE) or []
    current_headlines = {alert.get("headline") for alert in alerts_data if alert.get("headline")}

    with threading.Lock():
        new_headlines = current_headlines - broadcasted_alert_headlines
        if new_headlines:
            logging.info(f"Found {len(new_headlines)} new alert(s) to broadcast immediately.")
            for headline in new_headlines:
                broadcast_to_subscribers(f"{get_alert_emoji(headline)} {headline}", "alerts")
            broadcasted_alert_headlines.update(new_headlines)
        broadcasted_alert_headlines.intersection_update(current_headlines)

def handle_periodic_weather_broadcasts(now, initial_broadcast=False):
    last_sent_iso = dispatcher_state.get("last_weather_update")
    should_send_now = False
    if initial_broadcast:
        should_send_now = True
    elif now.minute % settings.WEATHER_UPDATE_INTERVAL_MINS == 0:
        last_sent_time = datetime.fromisoformat(last_sent_iso) if last_sent_iso else datetime.min.replace(tzinfo=pytz.UTC)
        if (now - last_sent_time).total_seconds() > 60:
            should_send_now = True
    if should_send_now:
        current_weather_data = load_json(settings.WEATHER_CURRENT_FILE)
        if not current_weather_data: return
        temp_f, humidity = current_weather_data.get("temperature_f", "N/A"), current_weather_data.get("humidity", "N/A")
        if temp_f == "N/A" and humidity == "N/A": return
        logging.info("Broadcasting current weather update.")
        broadcast_to_subscribers(f"{PREFIX_WEATHER} Currently: {temp_f}°F, {humidity}%RH", "weather")
        dispatcher_state["last_weather_update"] = now.isoformat()
        save_json(settings.DISPATCHER_STATE_FILE, dispatcher_state)

def handle_daily_forecasts(now):
    global dispatcher_state
    for time_str in settings.FORECAST_SEND_TIMES:
        broadcast_time = datetime.strptime(time_str, "%H:%M").time()
        if now.time().hour != broadcast_time.hour or now.time().minute != broadcast_time.minute:
            continue
        last_sent_date_str = dispatcher_state.get(f"forecast_{time_str}_sent_date")
        if last_sent_date_str == str(now.date()):
            continue
        logging.info(f"Attempting to broadcast scheduled forecast for {time_str}.")
        forecast_data = load_json(settings.WEATHER_FORECAST_FILE)
        if not forecast_data or "periods" not in forecast_data:
            logging.warning(f"Forecast data not available for the {time_str} broadcast.")
            continue
        periods = forecast_data["periods"]
        is_morning = now.hour < 12
        if is_morning:
            period = _find_forecast_period(periods, now, is_daytime=True, target_date=now.date())
            p_name = period.get('name', 'Today') if period else 'Today'
        else:
            period = _find_forecast_period(periods, now, is_daytime=False, target_date=now.date())
            p_name = period.get('name', 'Tonight') if period else 'Tonight'
        if not period:
            period = _find_forecast_period(periods, now, is_daytime=None)
            p_name = period.get('name', 'Forecast') if period else 'Forecast'
        if not period:
            logging.warning(f"Could not find any relevant forecast period for {time_str} broadcast.")
            continue
        msg = _create_forecast_message(period)
        full_message = f"{PREFIX_FORECAST} {p_name}: {msg}."
        broadcast_to_subscribers(full_message, "scheduled_daily_forecast")
        with dispatcher_state_lock:
            dispatcher_state[f"forecast_{time_str}_sent_date"] = str(now.date())
            save_json(settings.DISPATCHER_STATE_FILE, dispatcher_state)

def handle_nws_alert_broadcasts(now):
    global dispatcher_state
    if now.minute % settings.WEATHER_ALERT_INTERVAL_MINS == 0:
        last_sent_iso = dispatcher_state.get("last_nws_alert_reminder")
        last_sent_time = datetime.fromisoformat(last_sent_iso) if last_sent_iso else datetime.min.replace(tzinfo=pytz.UTC)
        if (now - last_sent_time).total_seconds() > 60:
            alerts_data = load_json(settings.WEATHER_ALERTS_FILE) or []
            active_headlines = {alert.get("headline") for alert in alerts_data if alert.get("headline")}
            if not active_headlines: return
            logging.info(f"Sending {len(active_headlines)} active NWS alert reminder(s).")
            for headline in active_headlines:
                broadcast_to_subscribers(f"{get_alert_emoji(headline)} {headline}", "alerts")
            with dispatcher_state_lock:
                dispatcher_state["last_nws_alert_reminder"] = now.isoformat()
                save_json(settings.DISPATCHER_STATE_FILE, dispatcher_state)

def handle_custom_broadcasts(now):
    dispatcher_file_path = settings.DISPATCHER_JOBS_FILE
    lock_path = dispatcher_file_path + ".lock"

    with file_lock(lock_path):
        if not os.path.exists(dispatcher_file_path): return
        try:
            jobs = load_json(dispatcher_file_path)
            if not isinstance(jobs, list):
                logging.warning(f"{dispatcher_file_path} is not a valid JSON list.")
                return
        except Exception as e:
            logging.warning(f"Could not read or parse {dispatcher_file_path}: {e}")
            return
        
        jobs_modified = False
        for index, job in enumerate(jobs):
            if not job.get("enabled", False):
                continue

            is_active = False
            
            if "start_datetime" in job and job["start_datetime"]:
                try:
                    start_dt = local_tz.localize(datetime.fromisoformat(job["start_datetime"]))
                    stop_dt = local_tz.localize(datetime.fromisoformat(job["stop_datetime"]))
                    if start_dt <= now <= stop_dt:
                        is_active = True
                except (ValueError, KeyError, TypeError) as e:
                    logging.warning(f"Skipping event job due to invalid datetime: {e} in job {job.get('name')}")
                    continue
            else:
                try:
                    day_map = {0: "MON", 1: "TUE", 2: "WED", 3: "THU", 4: "FRI", 5: "SAT", 6: "SUN"}
                    today_str = day_map[now.weekday()]
                    start_t = datetime.strptime(job["start_time"], "%H:%M").time()
                    stop_t = datetime.strptime(job["stop_time"], "%H:%M").time()
                    if today_str in job.get("days", []) and start_t <= now.time() <= stop_t:
                        is_active = True
                except (ValueError, KeyError, TypeError) as e:
                    logging.warning(f"Skipping recurring job due to invalid time: {e} in job {job.get('name')}")
                    continue

            if is_active:
                last_sent_iso = job.get("last_sent")
                interval_mins = job.get("interval_mins", 60)
                if _has_time_elapsed(last_sent_iso, now, interval_mins):
                    content = job.get("content")
                    if content:
                        logging.info(f"Sending custom broadcast for job '{job.get('name')}': {content}")
                        send_meshtastic_message(f"{PREFIX_SCHEDULED} {content}")
                        
                        jobs[index]["last_sent"] = now.isoformat()
                        jobs_modified = True
        
        if jobs_modified:
            save_json(dispatcher_file_path, jobs)

def update_dispatcher_status(now=None):
    status_data = {"radio_connected": (iface is not None), "last_update": datetime.now(local_tz).isoformat()}
    save_json(settings.DISPATCHER_STATUS_FILE, status_data)

def parse_command_text(text: str) -> tuple[str, str]:
    normalized_text = text.lower().strip()
    parts = normalized_text.split('/', 1)
    command_word = parts[0].strip()
    args = parts[1].strip() if len(parts) > 1 else ""
    return command_word, args

# --- NEW: Admin check helper function ---
def is_admin(sender_id):
    """Checks if the sender has admin privileges by looking for an 'ADMIN' tag."""
    with subscribers_lock:
        user_data = subscribers.get(sender_id, {})
        # Ensure tags are treated as a list and the check is case-insensitive
        tags = [tag.upper() for tag in user_data.get("tags", [])]
        return "ADMIN" in tags

def _cmd_get_forecast(sender, args):
    return {"response": get_current_forecast_message(), "no_prefix": True}

def _cmd_subscribe(sender, args):
    with subscribers_lock:
        if not subscribers.get(sender):
            subscribers[sender] = {"alerts": True, "weather": True, "scheduled_daily_forecast": True, "blocked": False}
            save_json_locked(settings.SUBSCRIBERS_FILE, subscribers)
        return None

def _cmd_unsubscribe(sender, args):
    with subscribers_lock:
        if sender in subscribers:
            del subscribers[sender]
            save_json_locked(settings.SUBSCRIBERS_FILE, subscribers)
        return None

def _cmd_set_name(sender, args):
    if not args: return "Invalid format. Use: name/YourName"
    user_name = args.strip().split()[0]
    with subscribers_lock:
        if sender not in subscribers:
            subscribers[sender] = {"alerts": True, "weather": True, "scheduled_daily_forecast": True, "blocked": False}
        subscribers[sender]['name'] = user_name
        save_json_locked(settings.SUBSCRIBERS_FILE, subscribers)
    return None

def _cmd_set_phone(sender, args):
    usage = "Invalid format. Use: phone/1/number or phone/2/number"
    if not args:
        return usage

    try:
        phone_index, phone_number = args.split('/', 1)
        phone_index = phone_index.strip()
        phone_number = phone_number.strip()
        if phone_index not in ['1', '2'] or not phone_number:
            raise ValueError()
    except ValueError:
        return usage

    key = f"phone_{phone_index}"
    with subscribers_lock:
        if sender not in subscribers:
            subscribers[sender] = {"alerts": True, "weather": True, "scheduled_daily_forecast": True, "blocked": False}
        subscribers[sender][key] = phone_number
        save_json_locked(settings.SUBSCRIBERS_FILE, subscribers)
    
    return f"Phone {phone_index} set successfully."

def _cmd_set_address(sender, args):
    if not args: return "Invalid format. Use: address/123 Main St, Your City"
    address = args.strip()
    with subscribers_lock:
        if sender not in subscribers:
            subscribers[sender] = {"alerts": True, "weather": True, "scheduled_daily_forecast": True, "blocked": False}
        subscribers[sender]['address'] = address
        save_json_locked(settings.SUBSCRIBERS_FILE, subscribers)
    return f"Address set."

def _cmd_toggle_service(sender, args):
    parts = args.split()
    if len(parts) != 2: return f"Invalid command. Usage: {parts[0]} on|off"
    service, status = parts
    if status not in ["on", "off"]: return f"Invalid status '{status}'. Use 'on' or 'off'."
    with subscribers_lock:
        if not subscribers.get(sender): return "You must be subscribed first. Send 'subscribe'."
        key_map = {"alerts": "alerts", "weather": "weather", "forecasts": "scheduled_daily_forecast"}
        subscribers[sender][key_map[service]] = (status == "on")
        save_json_locked(settings.SUBSCRIBERS_FILE, subscribers)
    return None

def _cmd_get_status(sender, args):
    with subscribers_lock:
        sub_data = subscribers.get(sender)
        if not sub_data: return "You are not subscribed."
        name_str = f"Name: {sub_data.get('name')} | " if sub_data.get('name') else ""
        tags_list = sub_data.get('tags', [])
        tags_str = f" | Tags: {', '.join(tags_list)}" if tags_list else ""
        return (f"{name_str}Alerts: {'on' if sub_data.get('alerts') else 'off'} | "
                f"Weather: {'on' if sub_data.get('weather') else 'off'} | "
                f"Forecasts: {'on' if sub_data.get('scheduled_daily_forecast') else 'off'}"
                f"{tags_str}")

def _cmd_send_email(sender, args):
    parts = args.split('/', 2)
    if len(parts) != 3: return "Invalid email format. Use: email/to@addr.com/subject/body"
    recipient, subject, body = [p.strip() for p in parts]
    if not (recipient and subject and body): return "Invalid email format. All parts are required."
    logging.info(f"Queueing email from {sender} to {recipient}")
    task = {"recipient": recipient, "subject": subject, "body": body, "sender_node": sender}
    with subscribers_lock:
        messages = load_json(settings.OUTGOING_EMAIL_FILE) or []
        messages.append(task)
        save_json(settings.OUTGOING_EMAIL_FILE, messages)
    return None

def _cmd_tagsend(sender, args):
    with subscribers_lock:
        sender_data = subscribers.get(sender)
        if not sender_data or not sender_data.get('node_tag_send', False):
            return "You are not authorized to use the tagsend command."
        sender_name = sender_data.get('name', sender)
    try:
        tags_str, message = args.split('/', 1)
        if not tags_str or not message: raise ValueError()
        target_tags = [tag.strip().upper() for tag in tags_str.split()]
    except ValueError:
        return "Invalid format. Use: tagsend/tag1 tag2.../message"

    recipient_ids = set()
    with subscribers_lock:
        for node_id, sub_data in subscribers.items():
            if any(tag in sub_data.get('tags', []) for tag in target_tags):
                recipient_ids.add(node_id)
    if not recipient_ids:
        return f"No users found with tags: {', '.join(target_tags)}"
    formatted_message = f"[{', '.join(target_tags)}] {sender_name}\n{message}"
    for recipient_id in recipient_ids:
        send_meshtastic_message(formatted_message, destinationId=recipient_id)
    return None

def _cmd_help(sender, args):
    return ("Cmds:\nwx (weather)\nstatus\n?\nsubscribe\nunsubscribe\n"
            "alerts on|off\nweather on|off\nforecasts on|off\n"
            "name/YourName\nphone/1|2/number\naddress/your address\n"
            "email/to/subj/body\ntagsend/tags/msg")

def _cmd_sos_status(sender, args):
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        active_sos_events = [e for e in sos_log if e.get("active")]

    if not active_sos_events:
        return "No active SOS alerts at this time."

    response_parts = ["ACTIVE ALERTS:"]
    with subscribers_lock:
        for i, sos in enumerate(active_sos_events, 1):
            sender_name = subscribers.get(sos['node_id'], {}).get('name', sos['node_id'])
            responding_names = [subscribers.get(r_id, {}).get('name', r_id) for r_id in sos.get('responding_list', [])]
            responding_str = ", ".join(responding_names) if responding_names else "None"
            response_parts.append(f"{i}. {sos['sos_type']} from {sender_name} (Responding: {responding_str})")
    
    return "\n".join(response_parts)

# --- NEW: Admin command for email blocklist ---
def _cmd_block_email(sender, args):
    if not is_admin(sender):
        return "Access Denied."
    
    blocklist_path = settings.EMAIL_BLOCKLIST_FILE
    
    if not args: # List current blocklist
        blocked_emails = load_json(blocklist_path) or []
        if not blocked_emails:
            return "Email blocklist is empty."
        else:
            return "Blocked:\n" + "\n".join(blocked_emails)
            
    email_to_block = args.strip().lower()
    with file_lock(blocklist_path + ".lock"):
        blocked_emails = load_json(blocklist_path) or []
        if email_to_block not in blocked_emails:
            blocked_emails.append(email_to_block)
            save_json(blocklist_path, blocked_emails)
            return f"Blocked: {email_to_block}"
        else:
            return f"{email_to_block} is already blocked."

# --- NEW: Admin command for email unblocking ---
def _cmd_unblock_email(sender, args):
    if not is_admin(sender):
        return "Access Denied."
        
    if not args:
        return "Usage: unblock/email@address.com"
        
    blocklist_path = settings.EMAIL_BLOCKLIST_FILE
    email_to_unblock = args.strip().lower()
    
    with file_lock(blocklist_path + ".lock"):
        blocked_emails = load_json(blocklist_path) or []
        if email_to_unblock in blocked_emails:
            blocked_emails.remove(email_to_unblock)
            save_json(blocklist_path, blocked_emails)
            return f"Unblocked: {email_to_unblock}"
        else:
            return f"{email_to_unblock} was not on the blocklist."

# --- NEW: tagin/tagout commands ---
def _cmd_tagin(sender, args):
    tag_to_join = args.strip().upper()
    if not tag_to_join:
        return "Usage: tagin/TAGNAME"

    # Optional: Check if user has the tag they are trying to join
    with subscribers_lock:
        user_tags = subscribers.get(sender, {}).get('tags', [])
        if tag_to_join not in user_tags:
            return f"You do not have the '{tag_to_join}' tag. Cannot join channel."

    with file_lock(settings.NODE_STATUS_FILE + ".lock"):
        node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
        if sender not in node_statuses:
            node_statuses[sender] = {}
        node_statuses[sender]['active_tag_channel'] = tag_to_join
        save_json(settings.NODE_STATUS_FILE, node_statuses)
    
    return f"You are now transmitting to {tag_to_join} tagged users. Send 'tagout' to exit."

def _cmd_tagout(sender, args):
    with file_lock(settings.NODE_STATUS_FILE + ".lock"):
        node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
        if node_statuses.get(sender, {}).get('active_tag_channel'):
            # Using .pop() safely removes the key
            node_statuses[sender].pop('active_tag_channel', None)
            # If the user's status object is now empty, we can remove it
            if not node_statuses[sender]:
                del node_statuses[sender]
            save_json(settings.NODE_STATUS_FILE, node_statuses)
            return "You have exited the tag."
        else:
            return "You are not in a tag."

COMMAND_HANDLERS = {
    "subscribe": _cmd_subscribe, "unsubscribe": _cmd_unsubscribe,
    "name": _cmd_set_name,
    "phone": _cmd_set_phone,
    "address": _cmd_set_address,
    "alerts": _cmd_toggle_service,
    "weather": _cmd_toggle_service, "forecasts": _cmd_toggle_service,
    "status": _cmd_get_status, "email": _cmd_send_email,
    "tagsend": _cmd_tagsend,
    "wx": _cmd_get_forecast,
    "?": _cmd_help,
    "active": _cmd_sos_status,
    "alertstatus": _cmd_sos_status,
    "block": _cmd_block_email,
    "unblock": _cmd_unblock_email,
    "tagin": _cmd_tagin,
    "tagout": _cmd_tagout,
}

def handle_meshtastic_command(sender, command_text):
    command_word, args = parse_command_text(command_text)
    if command_word in ["alerts", "weather", "forecasts"]:
        args = f"{command_word} {args}".strip()
    handler = COMMAND_HANDLERS.get(command_word)
    if handler:
        logging.info(f"Processing command '{command_word}' with args '{args}' for sender {sender}")
        result = handler(sender, args)
        if result is not None:
            response, add_bot_prefix = result, True
            if isinstance(result, dict):
                response, add_bot_prefix = result.get("response"), not result.get("no_prefix")
            if response:
                full_response = f"{PREFIX_BOT_RESPONSE} {response}" if add_bot_prefix else response
                send_meshtastic_message(full_response, destinationId=sender, wantAck=True)

def retry_queued_messages_for_node(node_id):
    with dm_queue_lock:
        queue = load_json(settings.FAILED_DM_QUEUE_FILE) or []
        if not queue: return
        messages_for_node = [msg for msg in queue if msg.get("destination_id") == node_id]
        if not messages_for_node: return
        logging.info(f"Node {node_id} is online. Retrying {len(messages_for_node)} queued message(s).")
        remaining_messages = [msg for msg in queue if msg.get("destination_id") != node_id]
        save_json(settings.FAILED_DM_QUEUE_FILE, remaining_messages)
    for msg in messages_for_node:
        send_meshtastic_message(text=msg["text"], destinationId=msg["destination_id"], wantAck=True)
        time.sleep(MIN_SEND_INTERVAL_SECONDS)

def on_meshtastic_message(packet, interface):
    global gateway_node_id, node_last_heard_cache, node_last_heard_cache_lock
    decoded = packet.get("decoded", {})
    if decoded.get("portnum") != "TEXT_MESSAGE_APP":
        return

    text = decoded.get("text", "").strip()
    sender = packet.get("fromId")
    destination_id = packet.get("toId")

    if not text or not sender:
        return

    if sender:
        with node_last_heard_cache_lock:
            node_last_heard_cache[sender] = time.time()
        retry_queued_messages_for_node(sender)

    is_dm_to_gateway = (destination_id == gateway_node_id)    
    log_channel_message(sender, text, is_dm=is_dm_to_gateway)

    if not is_dm_to_gateway:
        return
    
    with subscribers_lock:
        if subscribers.get(sender, {}).get('blocked', False):
            logging.info(f"Ignoring command from blocked user: {sender}")
            return

    if text.startswith(BOT_MESSAGE_PREFIXES):
        return

    command_queue.put((sender, text))

def on_meshtastic_message(packet, interface):
    global gateway_node_id, node_last_heard_cache, node_last_heard_cache_lock
    decoded = packet.get("decoded", {})
    if decoded.get("portnum") != "TEXT_MESSAGE_APP":
        return

    text = decoded.get("text", "").strip()
    sender = packet.get("fromId")
    destination_id = packet.get("toId")

    if not text or not sender:
        return

    if sender:
        with node_last_heard_cache_lock:
            node_last_heard_cache[sender] = time.time()
        retry_queued_messages_for_node(sender)

    is_dm_to_gateway = (destination_id == gateway_node_id)    
    log_channel_message(sender, text, is_dm=is_dm_to_gateway)

    if not is_dm_to_gateway:
        return
    
    with subscribers_lock:
        if subscribers.get(sender, {}).get('blocked', False):
            logging.info(f"Ignoring command from blocked user: {sender}")
            return

    if text.startswith(BOT_MESSAGE_PREFIXES):
        return

    # --- NEW: tagin/tagout stateful logic ---
    node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
    active_tag_channel = node_statuses.get(sender, {}).get('active_tag_channel')
    
    command_word, _ = parse_command_text(text)
    
    # Always allow tagin/tagout commands to be processed
    if command_word in ["tagin", "tagout"]:
        command_queue.put((sender, text))
        return

    if active_tag_channel:
        # User is in a tag channel. Check if the message is a standard command.
        # If it's NOT a standard command, treat it as a message for the tag channel.
        if command_word not in COMMAND_HANDLERS and command_word.upper() not in SOS_COMMANDS and command_word.upper() not in CLEAR_COMMANDS and command_word.upper() not in ACK_COMMANDS.union(RESPONDING_COMMANDS):
            logging.info(f"User {sender} is in tag channel '{active_tag_channel}'. Rerouting message.")
            # Re-route the message by creating a tagsend command and putting it on the queue
            tagsend_command_text = f"tagsend/{active_tag_channel}/{text}"
            command_queue.put((sender, tagsend_command_text))
            return # Stop further processing of the original message

    # If not in a tag channel, or if it was a standard command, process normally.
    command_queue.put((sender, text))

def _queue_sos_email_notification(sos_code, subject, body, extra_recipients=None):
    email_enabled_map = {
        "SOS": settings.SOS_EMAIL_ENABLED, "SOSM": settings.SOSM_EMAIL_ENABLED,
        "SOSF": settings.SOSF_EMAIL_ENABLED, "SOSP": settings.SOSP_EMAIL_ENABLED
    }
    email_recipients_map = {
        "SOS": settings.SOS_EMAIL_RECIPIENTS, "SOSM": settings.SOSM_EMAIL_RECIPIENTS,
        "SOSF": settings.SOSF_EMAIL_RECIPIENTS, "SOSP": settings.SOSP_EMAIL_RECIPIENTS
    }

    if not email_enabled_map.get(sos_code):
        return

    system_recipients = set(email_recipients_map.get(sos_code, []))
    user_recipients = extra_recipients if extra_recipients else set()
    final_recipients = list(system_recipients.union(user_recipients))

    if not final_recipients:
        logging.warning(f"SOS email for {sos_code} is enabled, but no recipients are configured.")
        return

    logging.info(f"Queueing SOS email notification to: {final_recipients}")
    with file_lock(settings.OUTGOING_EMAIL_FILE + ".lock"):
        outgoing = load_json(settings.OUTGOING_EMAIL_FILE) or []
        for recipient in final_recipients:
            task = {
                "recipient": recipient, 
                "subject": subject, 
                "body": body, 
                "sender_node": "GuardianBridge",
                "is_sos": True
            }
            outgoing.append(task)
        save_json(settings.OUTGOING_EMAIL_FILE, outgoing)

def handle_sos_alert(sender_id, sos_code, message_payload):
    logging.info(f"SOS '{sos_code}' from {sender_id} with payload: '{message_payload}'. Initiating alert protocol.")
    
    if iface:
        try:
            logging.info(f"Requesting immediate position update from SOS node {sender_id}...")
            iface.sendPosition(destinationId=sender_id, wantResponse=True)
            time.sleep(1)
        except Exception as e:
            logging.error(f"Could not request position from {sender_id}: {e}")

    with subscribers_lock:
        sender_info = subscribers.get(sender_id, {})
        sender_name = sender_info.get('name', f"Unknown ({sender_id})")

    node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
    lat = node_statuses.get(sender_id, {}).get('latitude')
    lon = node_statuses.get(sender_id, {}).get('longitude')
    
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        sos_log.append({
            "timestamp": datetime.now(local_tz).isoformat(), "sos_type": sos_code,
            "node_id": sender_id, "user_info": sender_info, "active": True,
            "message_payload": message_payload, "latitude": lat, "longitude": lon,
            "acknowledged_by": [], "responding_list": [], "last_checkin_time": datetime.now(local_tz).isoformat(),
            "checkin_attempts": 0, "escalated_no_ack": False, "escalated_unresponsive": False
        })
        save_json(settings.SOS_LOG_FILE, sos_log)
    
    update_sos_status(sender_id, sos_code)

    mesh_recipients = set()
    email_recipients = set()
    with subscribers_lock:
        tagged_responders = {node_id for node_id, data in subscribers.items() if sos_code in data.get('tags', [])}
        mesh_recipients.update(tagged_responders)

    if sender_info.get('sos_notify'):
        contacts = [c.strip() for c in sender_info['sos_notify'].split(',') if c.strip()]
        for contact in contacts:
            if '@' in contact:
                email_recipients.add(contact.lower())
            elif contact.startswith('!'):
                mesh_recipients.add(contact)
            else:
                with subscribers_lock:
                    found_id = next((nid for nid, data in subscribers.items() if (data.get('name') or '').lower() == contact.lower()), None)
                    if found_id:
                        mesh_recipients.add(found_id)
    
    location_info = f"LKP: https://www.google.com/maps?q={lat},{lon}" if lat and lon else "Location not available."
    alert_message_1 = f"{PREFIX_SOS} {sos_code} from {sender_name}" + (f": {message_payload}" if message_payload else "")
    alert_message_2 = f"{PREFIX_SOS} {location_info}"

    info_parts = []
    if sender_info.get('full_name'):
        info_parts.append(sender_info['full_name'])
    if sender_info.get('phone_1'):
        info_parts.append(sender_info['phone_1'])
    if sender_info.get('phone_2'):
        info_parts.append(sender_info['phone_2'])

    address_dict = sender_info.get('address', {})
    if isinstance(address_dict, dict):
        if address_dict.get('street'):
            info_parts.append(address_dict['street'])
        if address_dict.get('city'):
            info_parts.append(address_dict['city'])
        
        state_zip_parts = [part for part in [address_dict.get('state'), address_dict.get('zip')] if part]
        if state_zip_parts:
            info_parts.append(' '.join(state_zip_parts))

    alert_message_3 = ""
    if info_parts:
        info_string = "\n".join(info_parts)
        full_info_message = f"{PREFIX_SOS} INFO:\n{info_string}"
        
        max_len = 200
        if len(full_info_message.encode('utf-8')) > max_len:
            overhead = len(f"{PREFIX_SOS} INFO:\n...".encode('utf-8'))
            info_string_bytes = info_string.encode('utf-8')
            truncated_bytes = info_string_bytes[:max_len - overhead]
            info_string = truncated_bytes.decode('utf-8', 'ignore').rsplit('\n', 1)[0]
            full_info_message = f"{PREFIX_SOS} INFO:\n{info_string}..."
        alert_message_3 = full_info_message

    logging.info(f"Relaying SOS alert to {len(mesh_recipients)} mesh nodes.")
    for r_id in mesh_recipients:
        send_meshtastic_message(alert_message_1, destinationId=r_id, wantAck=True)
        time.sleep(MIN_SEND_INTERVAL_SECONDS)
        send_meshtastic_message(alert_message_2, destinationId=r_id, wantAck=True)
        if alert_message_3:
            time.sleep(MIN_SEND_INTERVAL_SECONDS)
            send_meshtastic_message(alert_message_3, destinationId=r_id, wantAck=True)

    timestamp_str = get_formatted_timestamp()
    
    address_dict = sender_info.get('address', {})
    address_str = "N/A"
    if isinstance(address_dict, dict):
        address_parts = [
            address_dict.get('street', ''),
            address_dict.get('city', ''),
            address_dict.get('state', ''),
            address_dict.get('zip', '')
        ]
        address_str = ', '.join(part for part in address_parts if part) or "N/A"

    user_details = "\n".join([
        f"Full Name: {sender_info.get('full_name', 'N/A')}",
        f"Node ID: {sender_id}",
        f"Name: {sender_info.get('name', 'N/A')}",
        f"Phone 1: {sender_info.get('phone_1', 'N/A')}",
        f"Phone 2: {sender_info.get('phone_2', 'N/A')}",
        f"Address: {address_str}"
    ])

    location_url = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else "Location not available."
    email_subject = f"[GuardianBridge ALERT] {sos_code} from {sender_name}"
    email_body = (
        f"A {sos_code} alert was triggered by {sender_name} at {timestamp_str}.\n\n"
        f"Message: {message_payload or 'No message provided.'}\n\n"
        f"--- User Information ---\n{user_details}\n\n"
        f"--- Last Known Location ---\n{location_url}\n\n"
        "This is an automated alert."
    )
    _queue_sos_email_notification(sos_code, email_subject, email_body, extra_recipients=email_recipients)
    
    send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} Your {sos_code} has been received. Alerting assigned personnel.", destinationId=sender_id, wantAck=True)

def handle_sos_clear(sender_id, admin_clear=False):
    logging.info(f"SOS CLEAR initiated for {sender_id}." + (" (Admin)" if admin_clear else ""))
    
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        active_sos_entry = next((e for e in sos_log if e.get("node_id") == sender_id and e.get("active")), None)
        
        if not active_sos_entry:
            logging.warning(f"Received CLEAR for {sender_id}, but no active SOS was found.")
            if not admin_clear:
                send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} You have no active alert to clear.", destinationId=sender_id, wantAck=True)
            return
        
        active_sos_code = active_sos_entry["sos_type"]
        active_sos_entry["active"] = False
        save_json(settings.SOS_LOG_FILE, sos_log)
    
    update_sos_status(sender_id, None)

    with subscribers_lock:
        clearer_name = subscribers.get(sender_id, {}).get('name', sender_id)
        responders = {node_id for node_id, data in subscribers.items() if active_sos_code in data.get('tags', [])}
        responders.update(active_sos_entry.get("responding_list", []))
        responders.update(active_sos_entry.get("acknowledged_by", []))

    if responders:
        stand_down_message = f"STAND DOWN: {clearer_name} has cleared the {active_sos_code} alert."
        logging.info(f"Sending stand down message to {len(responders)} responders.")
        for responder_id in responders:
            send_meshtastic_message(stand_down_message, destinationId=responder_id, wantAck=True)
    
    timestamp_str = get_formatted_timestamp()
    original_user_name = active_sos_entry.get("user_info", {}).get("name", active_sos_entry.get("node_id"))
    message_payload = active_sos_entry.get("message_payload", "")
    payload_str = f": {message_payload}" if message_payload else ""
    
    email_subject = f"[GuardianBridge STAND DOWN] {active_sos_code} from {original_user_name}{payload_str}"
    email_body = (
        f"The {active_sos_code} alert originally triggered by {original_user_name} has been cleared.\n\n"
        f"Cleared By: {clearer_name} ({sender_id})\n"
        f"Time Cleared: {timestamp_str}\n\n"
        "All responding units can stand down."
    )
    _queue_sos_email_notification(active_sos_code, email_subject, email_body)

    if not admin_clear:
        send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} Your {active_sos_code} alert has been cleared.", destinationId=sender_id, wantAck=True)

def handle_sos_action_initial(sender_id, command):
    global user_interaction_state
    global user_interaction_state_lock
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        active_sos_events = [e for e in sos_log if e.get("active")]

    if not active_sos_events:
        send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} There are no active SOS alerts.", destinationId=sender_id, wantAck=True)
        return
    
    if len(active_sos_events) == 1:
        target_sos_id = active_sos_events[0]['node_id']
        if command in ACK_COMMANDS:
            handle_sos_ack(sender_id, target_sos_id)
        elif command in RESPONDING_COMMANDS:
            handle_sos_responding(sender_id, target_sos_id)
    else:
        with user_interaction_state_lock:
            user_interaction_state[sender_id] = "awaiting_sos_choice"
            with subscribers_lock:
                menu_text = "Multiple active alerts. Reply with command and number (e.g., ACK 2):\n"
                for i, sos in enumerate(active_sos_events, 1):
                    sender_name = subscribers.get(sos['node_id'], {}).get('name', sos['node_id'])
                    menu_text += f"{i}. {sos['sos_type']} from {sender_name}\n"
            send_meshtastic_message(menu_text, destinationId=sender_id, wantAck=True)

def handle_sos_choice(responder_id, command, choice_num):
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        active_sos_events = [e for e in sos_log if e.get("active")]
    
    if 0 < choice_num <= len(active_sos_events):
        target_sos_id = active_sos_events[choice_num - 1]['node_id']
        if command.upper() in ACK_COMMANDS:
            handle_sos_ack(responder_id, target_sos_id)
        elif command.upper() in RESPONDING_COMMANDS:
            handle_sos_responding(responder_id, target_sos_id)
    else:
        send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} Invalid selection. Please try again.", destinationId=responder_id, wantAck=True)

def handle_sos_ack(responder_id, target_sos_id):
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        active_sos = next((e for e in sos_log if e.get("node_id") == target_sos_id and e.get("active")), None)
        if not active_sos: return

        if responder_id not in active_sos.get("acknowledged_by", []):
            active_sos.setdefault("acknowledged_by", []).append(responder_id)
            save_json(settings.SOS_LOG_FILE, sos_log)
            logging.info(f"SOS from {target_sos_id} acknowledged by {responder_id}.")
            send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} Your ACK has been logged.", destinationId=responder_id, wantAck=True)
        else:
            send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} You have already acknowledged this alert.", destinationId=responder_id, wantAck=True)

def handle_sos_responding(responder_id, target_sos_id):
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        active_sos = next((e for e in sos_log if e.get("node_id") == target_sos_id and e.get("active")), None)
        if not active_sos:
            logging.warning(f"Received RESPONDING from {responder_id} for inactive/invalid SOS {target_sos_id}.")
            return

        active_sos.setdefault("responding_list", [])
        if responder_id in active_sos["responding_list"]:
            logging.info(f"User {responder_id} is already marked as responding. Ignoring duplicate command.")
            send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} You are already marked as responding to this alert.", destinationId=responder_id, wantAck=True)
            return
            
        active_sos["responding_list"].append(responder_id)
        if "acknowledged_by" in active_sos and responder_id in active_sos["acknowledged_by"]:
             active_sos["acknowledged_by"].remove(responder_id)
        save_json(settings.SOS_LOG_FILE, sos_log)

    with subscribers_lock:
        responder_name = subscribers.get(responder_id, {}).get('name', responder_id)
        sos_user_name = active_sos.get("user_info", {}).get("name", active_sos["node_id"])
    
    update_msg = f"[SOS UPDATE] {responder_name} is now also responding to the {active_sos['sos_type']} from {sos_user_name}."
    logging.info(update_msg)
    
    with subscribers_lock:
        all_participants = set(active_sos.get('acknowledged_by', []) + active_sos.get('responding_list', []))
        tagged_responders = {node_id for node_id, data in subscribers.items() if active_sos['sos_type'] in data.get('tags', [])}
        responders_to_notify = (all_participants.union(tagged_responders)) - {responder_id}

    for r_id in responders_to_notify:
        send_meshtastic_message(update_msg, destinationId=r_id, wantAck=True)

    sos_author_id = active_sos.get("node_id")
    if sos_author_id:
        with subscribers_lock:
            responding_names = [subscribers.get(r_id, {}).get('name', r_id) for r_id in active_sos["responding_list"]]
        names_str = ", ".join(responding_names)
        confirmation_for_author = f"{PREFIX_BOT_RESPONSE} Help is on the way. Responding: {names_str}."
        send_meshtastic_message(confirmation_for_author, destinationId=sos_author_id, wantAck=True)
    
    send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} You are now marked as responding.", destinationId=responder_id, wantAck=True)

def handle_sos_checkin_response(sender_id):
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        active_sos = next((e for e in sos_log if e.get("node_id") == sender_id and e.get("active")), None)
        if not active_sos: return
        
        active_sos["last_checkin_time"] = datetime.now(local_tz).isoformat()
        active_sos["checkin_attempts"] = 0
        save_json(settings.SOS_LOG_FILE, sos_log)
        logging.info(f"Received check-in response from {sender_id}. Resetting attempt counter.")

def process_command_file(filepath):
    error_dir = os.path.join(settings.COMMANDS_DIR, "error")
    def quarantine_file(reason):
        logging.warning(f"Quarantining '{os.path.basename(filepath)}'. Reason: {reason}")
        if not os.path.exists(error_dir): os.makedirs(error_dir)
        try:
            os.rename(filepath, os.path.join(error_dir, f"{int(time.time())}_{os.path.basename(filepath)}"))
        except Exception as move_e:
            logging.error(f"Could not quarantine file {filepath}: {move_e}")
            try: os.remove(filepath)
            except: pass
    try:
        if not os.path.exists(filepath): return
        command_data = load_json(filepath)
        if not command_data:
            quarantine_file("Invalid or empty JSON.")
            return
        cmd = command_data.get("command")
        if cmd == "relay":
            recipients, text = command_data.get("recipients", []), command_data.get("text")
            if not all([recipients, text]):
                quarantine_file("Missing 'recipients' or 'text' for relay command.")
                return
            for r_id in recipients: send_meshtastic_message(f"{PREFIX_EMAIL} {text}", destinationId=r_id, wantAck=True)
        elif cmd == "broadcast":
            text = command_data.get("text")
            if text is None:
                quarantine_file("Missing 'text' for broadcast command.")
                return
            send_meshtastic_message(text)
        elif cmd == "dm":
            dest_id, r_name, text = command_data.get("destinationId"), command_data.get("recipient"), command_data.get("text")
            if not all([dest_id, r_name, text]):
                quarantine_file("Missing fields for dm command.")
                return
            send_meshtastic_message(text=text, destinationId=dest_id, wantAck=True, text_for_log=f"@{r_name} {text}")
        elif cmd == "tagsend":
            tags, text = command_data.get("tags", []), command_data.get("text")
            if not all([tags, text]):
                quarantine_file("Missing 'tags' or 'text' for tagsend command.")
                return
            target_tags = [t.strip().upper() for t in tags.split(',')] if isinstance(tags, str) else tags
            recipient_ids = {node_id for node_id, data in (load_json(settings.SUBSCRIBERS_FILE) or {}).items() if any(t in data.get('tags', []) for t in target_tags)}
            if recipient_ids:
                logging.info(f"Tag-based send to {len(recipient_ids)} recipients for tags: {target_tags}")
                for r_id in recipient_ids: send_meshtastic_message(text, destinationId=r_id, wantAck=True)
            else:
                logging.warning(f"No subscribers found for tags {target_tags}. Message not sent.")
        
        elif cmd == "admin_clear_sos":
            node_id = command_data.get("node_id")
            if node_id:
                logging.info(f"Processing admin request to clear SOS for node: {node_id}")
                handle_sos_clear(node_id, admin_clear=True)
            else:
                quarantine_file("Missing 'node_id' for admin_clear_sos command.")
                return
                
        else:
            logging.warning(f"Unknown file command '{cmd}' in {os.path.basename(filepath)}. Ignoring.")
        os.remove(filepath)
    except Exception as e:
        logging.error(f"Failed to process command file {filepath}: {e}", exc_info=True)
        quarantine_file("Unhandled exception during processing.")

def handle_preexisting_commands():
    command_dir = settings.COMMANDS_DIR
    if not os.path.exists(command_dir):
        os.makedirs(command_dir)
        return
    logging.info("Scanning for pre-existing command files...")
    for filename in os.listdir(command_dir):
        if filename.endswith('.json'):
            process_command_file(os.path.join(command_dir, filename))

def handle_active_sos_tasks(now):
    with file_lock(settings.SOS_LOG_FILE + ".lock"):
        sos_log = load_json(settings.SOS_LOG_FILE) or []
        active_sos_events = [e for e in sos_log if e.get("active")]
        
        if not active_sos_events:
            return
            
        log_needs_saving = False
        
        for active_sos in active_sos_events:
            if not active_sos.get("acknowledged_by") and not active_sos.get("responding_list") and not active_sos.get("escalated_no_ack", False):
                sos_start_time = datetime.fromisoformat(active_sos["timestamp"])
                if (now - sos_start_time).total_seconds() > settings.SOS_ACK_TIMEOUT_MINS * 60:
                    logging.warning(f"SOS from {active_sos['node_id']} has not been acknowledged after {settings.SOS_ACK_TIMEOUT_MINS} mins. Escalating network-wide.")
                    
                    sender_name = active_sos.get("user_info", {}).get("name", active_sos["node_id"])
                    payload = active_sos.get("message_payload", "")
                    
                    location_info = "Location not available."
                    lat, lon = active_sos.get("latitude"), active_sos.get("longitude")
                    if lat and lon:
                        location_info = f"LKP: https://www.google.com/maps?q={lat},{lon}"

                    alert_msg_1 = f"{PREFIX_SOS} {active_sos['sos_type']} from {sender_name}" + (f": {payload}" if payload else "")
                    alert_msg_2 = f"{PREFIX_SOS} {location_info}"
                    
                    broadcast_to_subscribers(f"[WIDE ALERT] {alert_msg_1}", "alerts")
                    time.sleep(MIN_SEND_INTERVAL_SECONDS)
                    broadcast_to_subscribers(f"[WIDE ALERT] {alert_msg_2}", "alerts")

                    active_sos["escalated_no_ack"] = True
                    log_needs_saving = True

            last_checkin_time = datetime.fromisoformat(active_sos.get("last_checkin_time"))
            if (now - last_checkin_time).total_seconds() > settings.SOS_CHECKIN_INTERVAL_MINS * 60:
                attempts = active_sos.get("checkin_attempts", 0)
                if attempts >= settings.SOS_CHECKIN_MAX_ATTEMPTS:
                    if not active_sos.get("escalated_unresponsive", False):
                        logging.warning(f"SOS user {active_sos['node_id']} is UNRESPONSIVE. Escalating alert.")
                        sender_name = active_sos.get("user_info", {}).get("name", active_sos["node_id"])
                        
                        with subscribers_lock:
                            all_participants = set(active_sos.get('acknowledged_by', []) + active_sos.get('responding_list', []))
                            tagged_responders = {node_id for node_id, data in subscribers.items() if active_sos['sos_type'] in data.get('tags', [])}
                            responders_to_notify = all_participants.union(tagged_responders)
                        
                        escalation_msg = f"[SOS ESCALATION] User {sender_name} is UNRESPONSIVE. Last check-in failed."
                        for r_id in responders_to_notify:
                            send_meshtastic_message(escalation_msg, destinationId=r_id, wantAck=True)

                        active_sos["escalated_unresponsive"] = True
                        log_needs_saving = True
                else:
                    logging.info(f"Sending check-in ping to {active_sos['node_id']} (Attempt {attempts + 1})")
                    send_meshtastic_message("[CHECK-IN] Are you OK? Please reply Y if you are.", destinationId=active_sos['node_id'], wantAck=True)
                    active_sos["last_checkin_time"] = now.isoformat()
                    active_sos["checkin_attempts"] = attempts + 1
                    log_needs_saving = True

        if log_needs_saving:
            save_json(settings.SOS_LOG_FILE, sos_log)

def run_periodic_task(target_func, interval_seconds, name):
    logging.info(f"Starting periodic task '{name}' with interval of {interval_seconds} seconds.")
    while True:
        try:
            now = datetime.now(local_tz)
            target_func(now)
        except Exception as e:
            logging.error(f"Error in periodic task '{name}': {e}", exc_info=True)
        
        time.sleep(interval_seconds - (time.time() % interval_seconds))

def main():
    global iface, subscribers, dispatcher_state, gateway_node_id, broadcasted_alert_headlines
    observer = Observer()
    try:
        iface = SerialInterface()
        logging.info("Waiting for Meshtastic interface to initialize...")
        time.sleep(2)
        node_num_int = iface.myInfo.my_node_num
        gateway_node_id = f'!{node_num_int:08x}'
        logging.info(f"Dispatcher started. Gateway Node ID: {gateway_node_id}")
    except Exception as e:
        logging.critical(f"Failed to connect to Meshtastic device: {e}", exc_info=True)
        update_dispatcher_status()
        exit(1)
    
    pub.subscribe(on_meshtastic_message, "meshtastic.receive")
    
    reload_subscribers()
    dispatcher_state = load_json(settings.DISPATCHER_STATE_FILE) or {}
    
    logging.info("Performing initial broadcast of active NWS alerts...")
    initial_alerts = load_json(settings.WEATHER_ALERTS_FILE) or []
    initial_headlines = {alert.get("headline") for alert in initial_alerts if alert.get("headline")}
    if initial_headlines:
        for headline in initial_headlines:
            broadcast_to_subscribers(f"{get_alert_emoji(headline)} {headline}", "alerts")
        with threading.Lock():
            broadcasted_alert_headlines.update(initial_headlines)
        logging.info(f"Broadcasted and initialized with {len(broadcasted_alert_headlines)} known alerts.")
    else:
        logging.info("No active NWS alerts found on startup.")

    for path in [settings.OUTGOING_EMAIL_FILE, CHANNEL0_LOG_FILE, settings.FAILED_DM_QUEUE_FILE, settings.SOS_LOG_FILE]:
        if not os.path.exists(path): save_json(path, [])
    if not os.path.exists(settings.NODE_STATUS_FILE): save_json(settings.NODE_STATUS_FILE, {})
        
    handle_preexisting_commands()
    
    event_handler = MasterFileEventHandler()
    observer.schedule(event_handler, settings.DATA_DIR, recursive=True)
    observer.start()
    logging.info(f"Started watching directory for changes: {settings.DATA_DIR}")
    
    now = datetime.now(local_tz)
    logging.info("Performing initial broadcast of weather conditions...")
    handle_periodic_weather_broadcasts(now, initial_broadcast=True)
    logging.info("Initial broadcasts complete. Starting main loop.")

    sender_thread = threading.Thread(target=sender_thread_worker, daemon=True)
    sender_thread.start()

    command_processor_thread = threading.Thread(target=command_processor_worker, daemon=True)
    command_processor_thread.start()

    tasks = [
        threading.Thread(target=run_periodic_task, args=(update_node_statuses, 60, 'update_node_statuses'), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_active_sos_tasks, 60, 'handle_active_sos_tasks'), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_nws_alert_broadcasts, 60, 'handle_nws_alert_broadcasts'), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_periodic_weather_broadcasts, 60, 'handle_periodic_weather_broadcasts'), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_daily_forecasts, 60, 'handle_daily_forecasts'), daemon=True),
        threading.Thread(target=run_periodic_task, args=(handle_custom_broadcasts, 60, 'handle_custom_broadcasts'), daemon=True),
        threading.Thread(target=run_periodic_task, args=(update_dispatcher_status, 30, 'update_dispatcher_status'), daemon=True)
    ]

    for task in tasks:
        task.start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt detected. Shutting down...")
    finally:
        logging.info("Stopping observer thread.")
        observer.stop()
        observer.join()
        command_queue.put((None, None))
        send_queue.put(None)
        iface_ref = iface
        iface = None
        update_dispatcher_status()
        if iface_ref: iface_ref.close()
        logging.info("Shutdown complete.")

if __name__ == "__main__":
    main()