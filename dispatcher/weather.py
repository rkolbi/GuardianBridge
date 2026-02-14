import logging
from datetime import date, datetime
from typing import Any, Dict, Optional

import pytz

import gb_db
import settings
from . import core
from .messaging import broadcast_to_subscribers, send_meshtastic_message


def highlight_extreme_conditions(text: Optional[str]) -> str:
    if not text:
        return ""
    text_lower = text.lower()
    flags = {emoji for keyword, emoji in core.EXTREME_FORECAST_FLAGS if keyword in text_lower}
    return " ".join(sorted(list(flags)))


def get_alert_emoji(headline: str) -> str:
    headline_lower = headline.lower()
    for keyword, emoji in core.NWS_ALERT_EMOJIS:
        if keyword in headline_lower:
            return emoji
    return core.PREFIX_ALERT


def _find_forecast_period(
    periods: list[Dict[str, Any]],
    now: datetime,
    is_daytime: Optional[bool] = None,
    target_date: Optional[date] = None,
) -> Optional[Dict[str, Any]]:
    target_date = target_date or now.date()
    for period in periods:
        try:
            start_time = datetime.fromisoformat(period.get("startTime", "").replace("Z", "+00:00"))
            if is_daytime is not None:
                if start_time.astimezone(core.local_tz).date() == target_date and period.get("isDaytime") == is_daytime:
                    return period
            else:
                end_time = datetime.fromisoformat(period.get("endTime", "").replace("Z", "+00:00"))
                if start_time <= now < end_time:
                    return period
        except (ValueError, KeyError):
            continue
    if is_daytime is None:
        for period in periods:
            try:
                start_time = datetime.fromisoformat(period.get("startTime", "").replace("Z", "+00:00"))
                if start_time >= now:
                    logging.info(f"No active forecast found. Falling back to next upcoming period: {period.get('name')}")
                    return period
            except (ValueError, KeyError):
                continue
    return None


def _create_forecast_message(period: Optional[Dict[str, Any]], on_demand: bool = False) -> str:
    if not period:
        return "Not available"
    name = period.get("name", "N/A")
    short_fc = period.get("shortForecast", "N/A")
    temp = period.get("temperature", "N/A")
    temp_unit = period.get("temperatureUnit", "")
    flags = highlight_extreme_conditions(short_fc)
    if on_demand:
        message = f"{name}: {short_fc}, {temp}\u00b0{temp_unit}"
    else:
        message = f"{short_fc}, {temp}\u00b0{temp_unit}"
    if flags:
        message += f" {flags}"
    return message


def get_current_forecast_message() -> str:
    forecast_data = core.load_json(settings.WEATHER_FORECAST_FILE)
    if not forecast_data or "periods" not in forecast_data:
        return "No forecast data available."
    now = datetime.now(core.local_tz)
    current_period = _find_forecast_period(forecast_data["periods"], now, is_daytime=None)
    if not current_period:
        return "Unable to retrieve current or upcoming forecast."
    return f"{core.PREFIX_FORECAST} {_create_forecast_message(current_period, on_demand=True)}"


def _has_time_elapsed(last_time_iso: Optional[str], now: datetime, interval_mins: int) -> bool:
    if not last_time_iso:
        return True
    last_sent_time = datetime.fromisoformat(last_time_iso)
    return (now - last_sent_time).total_seconds() >= interval_mins * 60


def handle_new_alert_broadcast() -> None:
    alerts_data = core.load_json(settings.WEATHER_ALERTS_FILE) or []
    current_headlines = {alert.get("headline") for alert in alerts_data if alert.get("headline")}

    with core.broadcasted_alert_lock:
        new_headlines = current_headlines - core.broadcasted_alert_headlines
        if new_headlines:
            logging.info(f"Found {len(new_headlines)} new alert(s) to broadcast immediately.")
            for headline in new_headlines:
                broadcast_to_subscribers(f"{get_alert_emoji(headline)} {headline}", "alerts")
            core.broadcasted_alert_headlines.update(new_headlines)
        core.broadcasted_alert_headlines.intersection_update(current_headlines)


def handle_periodic_weather_broadcasts(now: datetime, initial_broadcast: bool = False) -> None:
    with core.dispatcher_state_lock:
        last_sent_iso = core.dispatcher_state.get("last_weather_update")
    should_send_now = False
    if initial_broadcast:
        should_send_now = True
    elif now.minute % settings.WEATHER_UPDATE_INTERVAL_MINS == 0:
        last_sent_time = datetime.fromisoformat(last_sent_iso) if last_sent_iso else datetime.min.replace(tzinfo=pytz.UTC)
        if (now - last_sent_time).total_seconds() > 60:
            should_send_now = True
    if should_send_now:
        current_weather_data = core.load_json(settings.WEATHER_CURRENT_FILE)
        if not current_weather_data:
            return
        temp_f, humidity = current_weather_data.get("temperature_f", "N/A"), current_weather_data.get("humidity", "N/A")
        if temp_f == "N/A" and humidity == "N/A":
            return
        logging.info("Broadcasting current weather update.")
        broadcast_to_subscribers(f"{core.PREFIX_WEATHER} Currently: {temp_f}\u00b0F, {humidity}%RH", "weather")
        with core.dispatcher_state_lock:
            core.dispatcher_state["last_weather_update"] = now.isoformat()
            core.save_json(settings.DISPATCHER_STATE_FILE, core.dispatcher_state)


def handle_daily_forecasts(now: datetime) -> None:
    for time_str in settings.FORECAST_SEND_TIMES:
        broadcast_time = datetime.strptime(time_str, "%H:%M").time()
        if now.time().hour != broadcast_time.hour or now.time().minute != broadcast_time.minute:
            continue
        with core.dispatcher_state_lock:
            last_sent_date_str = core.dispatcher_state.get(f"forecast_{time_str}_sent_date")
        if last_sent_date_str == str(now.date()):
            continue
        logging.info(f"Attempting to broadcast scheduled forecast for {time_str}.")
        forecast_data = core.load_json(settings.WEATHER_FORECAST_FILE)
        if not forecast_data or "periods" not in forecast_data:
            logging.warning(f"Forecast data not available for the {time_str} broadcast.")
            continue
        periods = forecast_data["periods"]
        is_morning = now.hour < 12
        if is_morning:
            period = _find_forecast_period(periods, now, is_daytime=True, target_date=now.date())
            p_name = period.get("name", "Today") if period else "Today"
        else:
            period = _find_forecast_period(periods, now, is_daytime=False, target_date=now.date())
            p_name = period.get("name", "Tonight") if period else "Tonight"
        if not period:
            period = _find_forecast_period(periods, now, is_daytime=None)
            p_name = period.get("name", "Forecast") if period else "Forecast"
        if not period:
            logging.warning(f"Could not find any relevant forecast period for {time_str} broadcast.")
            continue
        msg = _create_forecast_message(period)
        full_message = f"{core.PREFIX_FORECAST} {p_name}: {msg}."
        broadcast_to_subscribers(full_message, "scheduled_daily_forecast")
        with core.dispatcher_state_lock:
            core.dispatcher_state[f"forecast_{time_str}_sent_date"] = str(now.date())
            core.save_json(settings.DISPATCHER_STATE_FILE, core.dispatcher_state)


def handle_nws_alert_broadcasts(now: datetime) -> None:
    if now.minute % settings.WEATHER_ALERT_INTERVAL_MINS == 0:
        with core.dispatcher_state_lock:
            last_sent_iso = core.dispatcher_state.get("last_nws_alert_reminder")
        last_sent_time = datetime.fromisoformat(last_sent_iso) if last_sent_iso else datetime.min.replace(tzinfo=pytz.UTC)
        if (now - last_sent_time).total_seconds() > 60:
            alerts_data = core.load_json(settings.WEATHER_ALERTS_FILE) or []
            active_headlines = {alert.get("headline") for alert in alerts_data if alert.get("headline")}
            if not active_headlines:
                return
            logging.info(f"Sending {len(active_headlines)} active NWS alert reminder(s).")
            for headline in active_headlines:
                broadcast_to_subscribers(f"{get_alert_emoji(headline)} {headline}", "alerts")
            with core.dispatcher_state_lock:
                core.dispatcher_state["last_nws_alert_reminder"] = now.isoformat()
                core.save_json(settings.DISPATCHER_STATE_FILE, core.dispatcher_state)


def handle_custom_broadcasts(now: datetime) -> None:
    jobs = gb_db.load_dispatcher_jobs() or []
    if not isinstance(jobs, list):
        logging.warning("Dispatcher jobs table is not a valid list.")
        return

    jobs_modified = False
    for index, job in enumerate(jobs):
        if not job.get("enabled", False):
            continue

        is_active = False

        if "start_datetime" in job and job["start_datetime"]:
            try:
                start_dt = datetime.fromisoformat(job["start_datetime"])
                stop_dt = datetime.fromisoformat(job["stop_datetime"])
                if start_dt.tzinfo is None:
                    start_dt = core.local_tz.localize(start_dt)
                if stop_dt.tzinfo is None:
                    stop_dt = core.local_tz.localize(stop_dt)
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
                    send_meshtastic_message(f"{core.PREFIX_SCHEDULED} {content}")

                    jobs[index]["last_sent"] = now.isoformat()
                    jobs_modified = True

    if jobs_modified:
        gb_db.replace_dispatcher_jobs(jobs)
