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
SOS_COMMANDS = {"SOSP", "SOSF", "SOSM", "SOS"}
CLEAR_COMMANDS = {"CLEAR", "CANCEL", "SAFE"}


# --- GLOBAL VARIABLES & SETUP ---
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, 'INFO'), format="%(asctime)s [%(levelname)s] %(message)s")
local_tz = pytz.timezone(get_localzone_name())
iface = None
subscribers = {}
subscribers_lock = threading.Lock()
dispatcher_state = {}
log_lock = threading.Lock()
dm_queue_lock = threading.Lock()
node_last_heard_cache = {}
CHANNEL0_LOG_FILE = getattr(settings, 'CHANNEL0_LOG_FILE', '/opt/GuardianBridge/data/channel0_log.json')
gateway_node_id = None
user_last_command_time = {}
broadcasted_alert_headlines = set()

# --- Throttling mechanism ---
MIN_SEND_INTERVAL_SECONDS = 1
last_send_time = 0
send_lock = threading.Lock()

# --- Watchdog event handler ---
class MasterFileEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        
        filepath = event.src_path
        filename = os.path.basename(filepath)

        if filepath.startswith(settings.COMMANDS_DIR) and filename.endswith('.json'):
            logging.info(f"Watchdog event (COMMAND) for: {filename}")
            time.sleep(0.1)
            process_command_file(filepath)
        elif filename == os.path.basename(settings.SUBSCRIBERS_FILE):
            logging.info(f"Watchdog event (CONFIG) for: {filename}. Reloading subscribers...")
            time.sleep(0.1)
            reload_subscribers()
        elif filename == os.path.basename(settings.WEATHER_ALERTS_FILE):
            logging.info(f"Watchdog event (ALERT) for: {filename}. Checking for new alerts...")
            time.sleep(0.1)
            handle_new_alert_broadcast()

# --- UTILITY FUNCTIONS ---
@contextmanager
def file_lock(lock_file_path):
    """A context manager for file-based locking."""
    if os.path.exists(lock_file_path):
        logging.warning(f"Lock file {lock_file_path} already exists. Waiting...")
    
    retry_count = 0
    while retry_count < 10: # Wait for a maximum of 1 second
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
    """Saves JSON to a file with a lock."""
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
        new_entry = {"from": sender_id, "timestamp": get_log_timestamp(), "text": text, "is_dm": is_dm}
        log_data.append(new_entry)
        if len(log_data) > MAX_LOG_ENTRIES:
            log_data = log_data[-MAX_LOG_ENTRIES:]
        save_json(CHANNEL0_LOG_FILE, log_data)
        logging.debug(f"Logged message from {sender_id} (DM: {is_dm})")

def send_meshtastic_message(text, destination_id=None, text_for_log=None, no_timestamp=False):
    global last_send_time, node_last_heard_cache
    with send_lock:
        current_time = time.time()
        elapsed = current_time - last_send_time
        if elapsed < MIN_SEND_INTERVAL_SECONDS:
            wait_time = MIN_SEND_INTERVAL_SECONDS - elapsed
            logging.debug(f"Throttling send. Waiting for {wait_time:.2f} seconds.")
            time.sleep(wait_time)

        log_text = text_for_log if text_for_log is not None else text
        is_dm = destination_id is not None
        log_channel_message("GATEWAY", log_text, is_dm=is_dm)

        if not iface:
            logging.error("Meshtastic interface not available.")
            return

        if no_timestamp:
            full_text = text
        else:
            full_text = f"{get_formatted_timestamp()}\n{text}"
            
        kwargs = {"text": full_text}
        if destination_id:
            kwargs.update({"destinationId": destination_id, "wantAck": True})

        try:
            iface.sendText(**kwargs)
            logging.info(f"Sent: '{text}' -> {destination_id or 'Broadcast'}")
            if destination_id:
                node_last_heard_cache[destination_id] = time.time()
        except Exception as e:
            logging.warning(f"Failed to send message to {destination_id}: {e}. Queuing for retry.")
            if destination_id:
                with dm_queue_lock:
                    queue = load_json(settings.FAILED_DM_QUEUE_FILE) or []
                    queue.append({"destination_id": destination_id, "text": text, "timestamp": datetime.now(local_tz).isoformat()})
                    save_json(settings.FAILED_DM_QUEUE_FILE, queue)
            elif not destination_id:
                logging.error(f"Failed to send broadcast message: '{text}'")
        last_send_time = time.time()

def update_node_statuses():
    global node_last_heard_cache, gateway_node_id
    if not iface: return

    # Load existing statuses to preserve SOS flags and location data if a node is temporarily offline
    node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
    
    known_node_ids = set(iface.nodes.keys())
    known_node_ids.update(node_last_heard_cache.keys())

    for node_id in known_node_ids:
        # Skip the gateway node for now, we'll add it manually
        if node_id == gateway_node_id:
            continue
            
        node = iface.nodes.get(node_id)
        
        # Get existing data for this node to use as a fallback
        existing_node_data = node_statuses.get(node_id, {})
        current_sos_status = existing_node_data.get('sos')
        last_known_lat = existing_node_data.get('latitude')
        last_known_lon = existing_node_data.get('longitude')

        if node:
            # Node is online, get fresh data
            role_name = config_pb2.Config.DeviceConfig.Role.Name(node.get('role', 0))
            snr, hops_away, lib_last_heard = node.get('snr'), node.get('hopsAway'), node.get('lastHeard')
            # Get new location, which might be None if this packet didn't have position data
            lat, lon = node.get('latitude'), node.get('longitude')
        else:
            # If node not in interface, it's offline. Mark its role as UNKNOWN.
            role_name, snr, hops_away, lib_last_heard, lat, lon = "UNKNOWN", None, None, None, None, None
        
        last_heard_ts = node_last_heard_cache.get(node_id, lib_last_heard)
        
        node_statuses[node_id] = {
            "role": role_name, 
            "lastHeard": last_heard_ts, 
            "snr": snr, 
            "hopsAway": hops_away,
            # Use new coordinates if they exist, otherwise fall back to the last known coordinates
            "latitude": lat if lat is not None else last_known_lat,
            "longitude": lon if lon is not None else last_known_lon
        }
        if current_sos_status:
            node_statuses[node_id]['sos'] = current_sos_status

    # Manually add/update the gateway node's own status
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
    """Updates the SOS status for a node in node_status.json."""
    node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
    if node_id not in node_statuses:
        node_statuses[node_id] = {} # Create if not exists
    
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
            send_meshtastic_message(message, destination_id=sender_id)

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
        dispatcher_state[f"forecast_{time_str}_sent_date"] = str(now.date())
        save_json(settings.DISPATCHER_STATE_FILE, dispatcher_state)

def handle_nws_alert_broadcasts(now):
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
            # Check if the job is enabled before processing ---
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

def update_dispatcher_status():
    status_data = {"radio_connected": (iface is not None), "last_update": datetime.now(local_tz).isoformat()}
    save_json(settings.DISPATCHER_STATUS_FILE, status_data)

def parse_command_text(text: str) -> tuple[str, str]:
    normalized_text = text.lower().strip()
    if '/' in normalized_text:
        normalized_text = normalized_text.replace('/', ' ', 1)
    parts = normalized_text.split(maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else ""

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

    key = f"phone_{phone_index}" # Creates 'phone_1' or 'phone_2'
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
    return f"Address set." # Return confirmation

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
    formatted_message = f"[Tags: {', '.join(target_tags)}] From {sender_name}:\n{message}"
    for recipient_id in recipient_ids:
        send_meshtastic_message(formatted_message, destination_id=recipient_id)
    return None

def _cmd_help(sender, args):
    return ("Cmds:\nwx\nstatus\n?\nsubscribe\nunsubscribe\n"
            "alerts on|off\nweather on|off\nforecasts on|off\n"
            "name/YourName\nphone/1|2/number\naddress/your address\n"
            "email/to/subj/body\ntagsend/tags/message")

COMMAND_HANDLERS = {
    "subscribe": _cmd_subscribe, "unsubscribe": _cmd_unsubscribe,
    "name": _cmd_set_name,
    "phone": _cmd_set_phone,
    "address": _cmd_set_address,
    "alerts": _cmd_toggle_service,
    "weather": _cmd_toggle_service, "forecasts": _cmd_toggle_service,
    "status": _cmd_get_status, "email": _cmd_send_email,
    "tagsend": _cmd_tagsend, "wx": _cmd_get_forecast, "?": _cmd_help
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
                send_meshtastic_message(full_response, destination_id=sender)

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
        send_meshtastic_message(text=msg["text"], destination_id=msg["destination_id"])
        time.sleep(MIN_SEND_INTERVAL_SECONDS)

def on_meshtastic_message(packet, interface):
    global gateway_node_id, node_last_heard_cache
    decoded = packet.get("decoded", {})
    if decoded.get("portnum") == "TEXT_MESSAGE_APP":
        text = decoded.get("text", "").strip()
        text_upper = text.upper()
        sender = packet.get("fromId")

        if sender:
            node_last_heard_cache[sender] = time.time()

        destination_id = packet.get("toId")
        if text and sender:
            retry_queued_messages_for_node(sender)
            is_direct_message = (destination_id == gateway_node_id)
            log_channel_message(sender, text, is_dm=is_direct_message)
            if not is_direct_message: return

            with subscribers_lock:
                if subscribers.get(sender, {}).get('blocked', False):
                    logging.info(f"Ignoring command from blocked user: {sender}")
                    return

            current_time = time.time()
            if current_time - user_last_command_time.get(sender, 0) < COMMAND_COOLDOWN_SECONDS:
                logging.warning(f"User {sender} rate-limited. Ignoring command: '{text}'")
                return
            
            if text.startswith(BOT_MESSAGE_PREFIXES): return

            # --- SOS & Clear Command Handling ---
            if text_upper in SOS_COMMANDS:
                user_last_command_time[sender] = current_time
                handle_sos_alert(sender, text_upper)
                return

            if text_upper in CLEAR_COMMANDS:
                user_last_command_time[sender] = current_time
                handle_sos_clear(sender)
                return

            command_word = text.lower().strip().split('/')[0].split()[0]
            if command_word in COMMAND_HANDLERS:
                user_last_command_time[sender] = current_time 
                handle_meshtastic_command(sender, text)

def handle_sos_alert(sender_id, sos_code):
    """Handles triggering an SOS alert by sending two messages:
    1. The critical alert with location.
    2. A follow-up with detailed contact/address info.
    """
    logging.info(f"SOS '{sos_code}' detected from {sender_id}. Initiating alert protocol.")

    if iface:
        try:
            logging.info(f"Requesting immediate position update from SOS node {sender_id}...")
            iface.sendPosition(destinationId=sender_id, wantResponse=True)
        except Exception as e:
            logging.error(f"Could not request position from {sender_id}: {e}")

    # 1. Update node status and log the event
    update_sos_status(sender_id, sos_code)
    
    with subscribers_lock:
        sender_info = subscribers.get(sender_id, {})
        sender_name = sender_info.get('name', f"Unknown ({sender_id})")

    sos_log = load_json(settings.SOS_LOG_FILE) or []
    sos_log.append({
        "timestamp": datetime.now(local_tz).isoformat(),
        "sos_type": sos_code,
        "node_id": sender_id,
        "user_info": sender_info
    })
    save_json(settings.SOS_LOG_FILE, sos_log)

    # 2. Find responders
    tag_to_alert = sos_code
    with subscribers_lock:
        responders = [node_id for node_id, data in subscribers.items() if tag_to_alert in data.get('tags', [])]
    
    if not responders:
        logging.warning(f"No responders found with tag '{tag_to_alert}' for SOS from {sender_id}.")
        return

    # 3. Get location from the node status file
    node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
    sender_node_data = node_statuses.get(sender_id, {})
    lat, lon = sender_node_data.get('latitude'), sender_node_data.get('longitude')
    
    location_info = "Location not available."
    if lat and lon:
        location_link = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
        location_info = f"LKP: {location_link}"
    
    # 4. Construct and send the two messages
    
    # --- MESSAGE 1: The Critical Alert ---
    alert_message_1 = f"{PREFIX_SOS} {sos_code} from {sender_name}\n{location_info}"

    # --- MESSAGE 2: Detailed Supplementary Info ---
    message_lines = [f"🆘{sender_name} INFO:"]
    
    # Add full name if it exists
    if sender_info.get("full_name"):
        message_lines.append(sender_info["full_name"])
        
    # Add phone numbers if they exist
    if sender_info.get("phone_1"):
        message_lines.append(f"tel: {sender_info['phone_1']}")
    if sender_info.get("phone_2"):
        message_lines.append(f"tel: {sender_info['phone_2']}")
        
    # Add formatted address if it exists and is a dictionary
    address_obj = sender_info.get("address")
    if isinstance(address_obj, dict):
        if address_obj.get("street"):
            message_lines.append(address_obj["street"])
        
        city_state_line = []
        if address_obj.get("city"):
            city_state_line.append(address_obj["city"])
        if address_obj.get("state"):
            city_state_line.append(address_obj["state"])
        if city_state_line:
             message_lines.append(", ".join(city_state_line))

        if address_obj.get("zip"):
            message_lines.append(address_obj["zip"])

    alert_message_2 = "\n".join(message_lines)

    # 5. Relay messages to all responders
    logging.info(f"Relaying SOS alert to {len(responders)} responders.")
    for responder_id in responders:
        # Send the first, most important message
        send_meshtastic_message(alert_message_1, destination_id=responder_id)
        
        # Short pause before sending the second message
        time.sleep(MIN_SEND_INTERVAL_SECONDS) 
        
        # Send the supplementary details if there's anything to send besides the header
        if len(message_lines) > 1:
            send_meshtastic_message(alert_message_2, destination_id=responder_id, no_timestamp=True)

def handle_sos_clear(sender_id):
    """Handles clearing an active SOS."""
    logging.info(f"SOS CLEAR detected from {sender_id}.")

    # 1. Check for an active SOS to clear
    node_statuses = load_json(settings.NODE_STATUS_FILE) or {}
    active_sos_code = node_statuses.get(sender_id, {}).get('sos')

    if not active_sos_code:
        logging.warning(f"Received CLEAR from {sender_id}, but no active SOS was found for them.")
        send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} You have no active alert to clear.", destination_id=sender_id)
        return
        
    # 2. Find responders who received the initial alert
    tag_to_alert = active_sos_code
    with subscribers_lock:
        sender_name = subscribers.get(sender_id, {}).get('name', sender_id)
        responders = [node_id for node_id, data in subscribers.items() if tag_to_alert in data.get('tags', [])]

    # 3. Send "STAND DOWN" notification
    if responders:
        stand_down_message = f"STAND DOWN: {sender_name} has cleared the {active_sos_code} alert."
        logging.info(f"Sending stand down message to {len(responders)} responders.")
        for responder_id in responders:
            send_meshtastic_message(stand_down_message, destination_id=responder_id)
    
    # 4. Clear the SOS status from node_status.json
    update_sos_status(sender_id, None)
    send_meshtastic_message(f"{PREFIX_BOT_RESPONSE} Your {active_sos_code} alert has been cleared.", destination_id=sender_id)

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
            for r_id in recipients: send_meshtastic_message(f"{PREFIX_EMAIL} {text}", destination_id=r_id)
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
            send_meshtastic_message(text=text, destination_id=dest_id, text_for_log=f"@{r_name} {text}")
        elif cmd == "tagsend":
            tags, text = command_data.get("tags", []), command_data.get("text")
            if not all([tags, text]):
                quarantine_file("Missing 'tags' or 'text' for tagsend command.")
                return
            target_tags = [t.strip().upper() for t in tags.split(',')] if isinstance(tags, str) else tags
            recipient_ids = {node_id for node_id, data in (load_json(settings.SUBSCRIBERS_FILE) or {}).items() if any(t in data.get('tags', []) for t in target_tags)}
            if recipient_ids:
                logging.info(f"Tag-based send to {len(recipient_ids)} recipients for tags: {target_tags}")
                for r_id in recipient_ids: send_meshtastic_message(text, destination_id=r_id)
            else:
                logging.warning(f"No subscribers found for tags {target_tags}. Message not sent.")
        
        # --- NEW: Handler for Admin Clear SOS Command ---
        elif cmd == "admin_clear_sos":
            node_id = command_data.get("node_id")
            if node_id:
                logging.info(f"Processing admin request to clear SOS for node: {node_id}")
                handle_sos_clear(node_id)
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
    
    try:
        while True:
            now = datetime.now(local_tz)
            update_dispatcher_status()
            update_node_statuses() 
            handle_nws_alert_broadcasts(now)
            handle_periodic_weather_broadcasts(now)
            handle_daily_forecasts(now)
            handle_custom_broadcasts(now)
            time_to_sleep = 60 - datetime.now(local_tz).second
            time.sleep(time_to_sleep if time_to_sleep > 0 else 1)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt detected. Shutting down...")
    finally:
        logging.info("Stopping observer thread.")
        observer.stop()
        observer.join()
        iface_ref = iface
        iface = None
        update_dispatcher_status()
        if iface_ref: iface_ref.close()
        logging.info("Shutdown complete.")

if __name__ == "__main__":
    main()
