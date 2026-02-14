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

# weather_fetcher.py

import os
import json
import datetime
import pytz
import logging
import requests
import time
import sys
from tzlocal import get_localzone_name
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import settings
from pathlib import Path

# Logging setup
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, "INFO"), format="%(asctime)s [%(levelname)s] %(message)s")

# Setup retrying session
session = requests.Session()
retry_strategy = Retry(
    total=settings.HTTP_RETRY_TOTAL,
    backoff_factor=settings.HTTP_RETRY_BACKOFF,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
session.headers.update({"User-Agent": settings.USER_AGENT})

# Utility functions
def fetch_nws_points():
    url = f"https://api.weather.gov/points/{settings.LATITUDE},{settings.LONGITUDE}"
    try:
        r = session.get(url, timeout=10)
        r.raise_for_status()
        return r.json().get("properties")
    except Exception as e:
        logging.error(f"Failed to fetch NWS point data: {e}")
        return None

def fetch_current_observation(station_id):
    url = f"https://api.weather.gov/stations/{station_id}/observations/latest"
    try:
        r = session.get(url, timeout=10)
        r.raise_for_status()
        if r.text:
            return r.json().get("properties")
        return None
    except requests.exceptions.JSONDecodeError:
        logging.warning(f"Station {station_id} returned a non-JSON response. It may have no current observation.")
        return None
    except Exception as e:
        logging.error(f"Failed to fetch current observation for station {station_id}: {e}")
        return None

def _parse_observation_timestamp(ts_value):
    if not ts_value:
        return None
    if isinstance(ts_value, str) and ts_value.endswith("Z"):
        ts_value = ts_value[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(ts_value)
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)

def _observation_is_fresh(obs, max_age_minutes):
    obs_ts_raw = obs.get("timestamp") if isinstance(obs, dict) else None
    obs_dt = _parse_observation_timestamp(obs_ts_raw)
    if obs_dt is None:
        return False, None
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    age_minutes = (now_utc - obs_dt).total_seconds() / 60.0
    return age_minutes <= max_age_minutes, age_minutes

def fetch_forecast_periods(forecast_url):
    try:
        r = session.get(forecast_url, timeout=10)
        r.raise_for_status()
        return r.json().get("properties", {}).get("periods", [])
    except Exception as e:
        logging.error(f"Failed to fetch forecast periods from {forecast_url}: {e}")
        return []

def fetch_alerts():
    url = f"https://api.weather.gov/alerts/active?point={settings.LATITUDE},{settings.LONGITUDE}"
    try:
        r = session.get(url, timeout=10)
        r.raise_for_status()
        return r.json().get("features", [])
    except Exception as e:
        logging.error(f"Failed to fetch alerts: {e}")
        return []

# Write helpers
def save_json(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    temp_path = filepath + ".tmp"
    with open(temp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(temp_path, filepath)

def acquire_lock(lock_path, max_age_seconds=1800):
    now = time.time()
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
        return True
    except FileExistsError:
        try:
            age = now - os.path.getmtime(lock_path)
        except OSError:
            age = None
        if age is not None and age > max_age_seconds:
            try:
                os.remove(lock_path)
            except OSError:
                return False
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w") as f:
                    f.write(str(os.getpid()))
                return True
            except OSError:
                return False
        return False

def release_lock(lock_path):
    try:
        os.remove(lock_path)
    except OSError:
        pass

# Main logic
if __name__ == "__main__":
    lock_path = os.path.join(settings.DATA_DIR, "weather_fetcher.lock")
    if not acquire_lock(lock_path, max_age_seconds=1800):
        logging.warning("Weather fetcher already running. Exiting.")
        sys.exit(0)

    try:
        local_tz = pytz.timezone(get_localzone_name())
        logging.info("Starting weather fetch cycle...")
        points = fetch_nws_points()

        if not points:
            logging.critical("Could not fetch NWS point data. Aborting fetch cycle.")
            sys.exit(1)

        try:
            forecast_url = points.get("forecast")
            stations_url = points.get("observationStations")
            
            obs = None 

            if stations_url:
                r = session.get(stations_url, timeout=10)
                r.raise_for_status()
                station_features = r.json().get("features", [])
                
                for station_feature in station_features:
                    station_id = station_feature.get("properties", {}).get("stationIdentifier")
                    if not station_id:
                        continue
                    
                    logging.info(f"Attempting to fetch data for station ID: {station_id}")
                    current_obs = fetch_current_observation(station_id)
                    
                    if current_obs and current_obs.get("temperature", {}).get("value") is not None:
                        is_fresh, age_minutes = _observation_is_fresh(
                            current_obs, settings.WEATHER_DATA_MAX_AGE_MINUTES
                        )
                        if is_fresh:
                            logging.info(f"Successfully found valid data from station: {station_id}")
                            obs = current_obs
                            obs["_station_id"] = station_id
                            obs["_age_minutes"] = age_minutes
                            break
                        else:
                            age_note = f"{age_minutes:.1f} min" if age_minutes is not None else "unknown age"
                            logging.warning(
                                f"Station {station_id} has stale observation data ({age_note}). Trying next station."
                            )
                    else:
                        logging.warning(f"Station {station_id} has no recent temperature data. Trying next station.")
            
            if obs:
                temp_c = obs.get("temperature", {}).get("value")
                humidity = obs.get("relativeHumidity", {}).get("value")
                obs_timestamp = obs.get("timestamp")
                station_id = obs.get("_station_id")
                obs_age_minutes = obs.get("_age_minutes")
                data = {
                    "temperature_f": round((temp_c * 9/5) + 32) if temp_c is not None else "N/A",
                    "humidity": round(humidity) if humidity is not None else "N/A",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "observation_time": obs_timestamp,
                    "station_id": station_id,
                    "observation_age_minutes": round(obs_age_minutes, 1) if obs_age_minutes is not None else None,
                }
                save_json(settings.WEATHER_CURRENT_FILE, data)
            else:
                logging.error("Could not retrieve valid observation data from any nearby station. Writing N/A.")
                data = {
                    "temperature_f": "N/A",
                    "humidity": "N/A",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "observation_time": None,
                    "station_id": None,
                    "observation_age_minutes": None,
                }
                save_json(settings.WEATHER_CURRENT_FILE, data)

            if forecast_url:
                forecast = fetch_forecast_periods(forecast_url)
                forecast_data = {
                    # --- TIMESTAMP CHANGE ---
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "periods": forecast
                }
                save_json(settings.WEATHER_FORECAST_FILE, forecast_data)

        except Exception as e:
            logging.error(f"An error occurred during weather/forecast fetch: {e}")

        logging.info("Fetching NWS alerts...")
        active_alerts_from_api = fetch_alerts()
        parsed_alerts = [
            {"event": a["properties"].get("event"), "headline": a["properties"].get("headline")}
            for a in active_alerts_from_api if a.get("properties")
        ]
        logging.info(f"Found {len(parsed_alerts)} active alerts. Overwriting alerts file.")
        save_json(settings.WEATHER_ALERTS_FILE, parsed_alerts)
        
        try:
            Path(settings.WEATHER_FETCHER_LASTRUN_FILE).touch()
        except Exception as e:
            logging.error(f"Could not create .lastrun file: {e}")
        logging.info("Weather fetch cycle complete.")
    finally:
        release_lock(lock_path)
