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
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

# Main logic
if __name__ == "__main__":
    local_tz = pytz.timezone(get_localzone_name())
    logging.info("Starting weather fetch cycle...")
    points = fetch_nws_points()

    if not points:
        logging.critical("Could not fetch NWS point data. Aborting fetch cycle.")
        exit(1)

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
                    logging.info(f"Successfully found valid data from station: {station_id}")
                    obs = current_obs
                    break
                else:
                    logging.warning(f"Station {station_id} has no recent temperature data. Trying next station.")
        
        if obs:
            temp_c = obs.get("temperature", {}).get("value")
            humidity = obs.get("relativeHumidity", {}).get("value")
            data = {
                "temperature_f": round((temp_c * 9/5) + 32) if temp_c is not None else "N/A",
                "humidity": round(humidity) if humidity is not None else "N/A",
                # --- TIMESTAMP CHANGE ---
                "timestamp": datetime.datetime.now(local_tz).strftime("%H:%M %m/%d")
            }
            save_json(settings.WEATHER_CURRENT_FILE, data)
        else:
            logging.error("Could not retrieve valid observation data from any nearby station. Writing N/A.")
            data = {
                "temperature_f": "N/A",
                "humidity": "N/A",
                # --- TIMESTAMP CHANGE ---
                "timestamp": datetime.datetime.now(local_tz).strftime("%H:%M %m/%d")
            }
            save_json(settings.WEATHER_CURRENT_FILE, data)

        if forecast_url:
            forecast = fetch_forecast_periods(forecast_url)
            forecast_data = {
                # --- TIMESTAMP CHANGE ---
                "timestamp": datetime.datetime.now(local_tz).strftime("%H:%M %m/%d"),
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
