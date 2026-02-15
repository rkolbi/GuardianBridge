import logging
import os
import re
import random
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Callable, Optional, Tuple

import gb_db
import settings
from . import core
from .email_queue import queue_email_task
from .messaging import send_meshtastic_message
from .sos import (
    handle_sos_ack,
    handle_sos_action_initial,
    handle_sos_alert,
    handle_sos_checkin_response,
    handle_sos_choice,
    handle_sos_clear,
    handle_sos_responding,
)
from .weather import get_current_forecast_message


def _utf8_len(text: str) -> int:
    return len(text.encode("utf-8"))


def _chunk_lines_by_bytes(lines: list[str], max_bytes: int) -> list[str]:
    if max_bytes < 1:
        return ["\n".join(lines)] if lines else [""]

    chunks: list[str] = []
    current: list[str] = []
    current_bytes = 0

    for line in lines:
        line_bytes = _utf8_len(line)
        extra_bytes = line_bytes + (1 if current else 0)
        if current and current_bytes + extra_bytes > max_bytes:
            chunks.append("\n".join(current))
            current = [line]
            current_bytes = line_bytes
        else:
            if current:
                current_bytes += 1 + line_bytes
                current.append(line)
            else:
                current = [line]
                current_bytes = line_bytes

    if current:
        chunks.append("\n".join(current))

    return chunks


def parse_command_text(text: str) -> tuple[str, str]:
    normalized_text = text.strip()
    sep_positions = [normalized_text.find(sep) for sep in ["/", ","] if sep in normalized_text]
    if sep_positions:
        split_pos = min(sep_positions)
        command_word = normalized_text[:split_pos].strip().lower()
        args = normalized_text[split_pos + 1 :].strip()
        if command_word != "?":
            command_word = command_word.rstrip("?!.,:;")
        return command_word, args
    parts = normalized_text.split(None, 1)
    command_word = parts[0].strip().lower() if parts else ""
    if command_word != "?":
        command_word = command_word.rstrip("?!.,:;")
    args = parts[1].strip() if len(parts) > 1 else ""
    return command_word, args


def is_admin(sender_id):
    """Checks if the sender has admin privileges by looking for an 'ADMIN' tag."""
    with core.subscribers_lock:
        user_data = core.subscribers.get(sender_id, {})
        tags = [tag.upper() for tag in user_data.get("tags", [])]
        return "ADMIN" in tags


TEMP_GROUP_NAME_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9_-]{1,31}$")
TEMP_GROUP_RESERVED_NAMES = {"ALL", "ADMIN", *core.SOS_COMMANDS}


def _normalize_channel_name(raw: str) -> str:
    token = (raw or "").strip()
    if not token:
        return ""
    token = token.split()[0].lstrip("@").upper()
    return token


def _is_valid_channel_name(name: str) -> bool:
    return bool(TEMP_GROUP_NAME_PATTERN.match(name))


def _is_reserved_channel_name(name: str) -> bool:
    return name in TEMP_GROUP_RESERVED_NAMES or name.startswith("SOS")


def _is_known_permanent_tag(tag_name: str) -> bool:
    with core.subscribers_lock:
        for sub_data in core.subscribers.values():
            tags = [str(t).upper() for t in sub_data.get("tags", []) if str(t).strip()]
            if tag_name in tags:
                return True
    return False


def _flag_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on"}


def _get_sender_subscriber_record(sender_id: str) -> dict[str, Any]:
    sender = str(sender_id or "").strip()
    if not sender:
        return {}
    db_record = gb_db.get_subscriber(sender, case_insensitive=True)
    if isinstance(db_record, dict):
        return db_record
    with core.subscribers_lock:
        direct = core.subscribers.get(sender)
        if isinstance(direct, dict):
            return direct
        sender_upper = sender.upper()
        for node_id, sub_data in core.subscribers.items():
            if str(node_id).upper() == sender_upper and isinstance(sub_data, dict):
                return sub_data
    return {}


def _is_temp_group_name(group_name: str) -> bool:
    return gb_db.get_temp_group(group_name) is not None


def _is_temp_group_locked(group_name: str) -> bool:
    group = gb_db.get_temp_group(group_name)
    return bool(group and group.get("locked"))


def _get_temp_group_ttl_days() -> int:
    try:
        ttl_days = int(getattr(settings, "TEMP_GROUP_TTL_DAYS", 14))
    except Exception:
        ttl_days = 14
    return max(1, ttl_days)


def cleanup_expired_temp_groups(now=None) -> int:
    if isinstance(now, datetime):
        now_ts = int(now.timestamp())
    else:
        now_ts = int(time.time())
    ttl_days = _get_temp_group_ttl_days()
    removed = gb_db.prune_expired_temp_groups(ttl_days, now_ts=now_ts)
    if removed > 0:
        logging.info(f"Pruned {removed} expired temporary group(s) (TTL: {ttl_days} days).")
    return removed


def handle_temp_group_expiry(now: Optional[datetime] = None) -> None:
    cleanup_expired_temp_groups(now)


def _cmd_get_forecast(sender: str, args: str) -> dict[str, Any]:
    return {"response": get_current_forecast_message(), "no_prefix": True}


def _cmd_hello(sender: str, args: str) -> dict[str, Any]:
    server_name = str(getattr(settings, "SERVER_NAME", "GuardianBridge") or "GuardianBridge").strip()
    server_version = str(getattr(settings, "SERVER_VERSION", "v1.4.0") or "v1.4.0").strip()
    if not server_name:
        server_name = "GuardianBridge"
    if not server_version:
        server_version = "v1.4.0"

    now_str = datetime.now(core.local_tz).strftime("%H:%M %m/%d %Z")

    current_weather_data = core.load_json(settings.WEATHER_CURRENT_FILE) or {}
    temp_f = current_weather_data.get("temperature_f", "N/A")
    humidity = current_weather_data.get("humidity", "N/A")
    if temp_f == "N/A" and humidity == "N/A":
        weather_line = f"{core.PREFIX_WEATHER} Current weather unavailable."
    else:
        weather_line = f"{core.PREFIX_WEATHER} Currently: {temp_f}\u00b0F, {humidity}%RH"

    forecast_line = get_current_forecast_message()
    response_lines = [
        f"{server_name} {server_version}",
        f"Time: {now_str}",
        weather_line,
        forecast_line,
    ]

    max_bytes = max(20, settings.MAX_MESH_TEXT_LEN)
    chunks = _chunk_lines_by_bytes(response_lines, max_bytes)
    return {"responses": chunks, "no_prefix": True}


def _cmd_subscribe(sender: str, args: str):
    with core.subscribers_lock:
        if not core.subscribers.get(sender):
            core.subscribers[sender] = {"alerts": True, "weather": True, "scheduled_daily_forecast": True, "blocked": False}
            core.save_json_locked(settings.SUBSCRIBERS_FILE, core.subscribers)
        return None


def _cmd_unsubscribe(sender: str, args: str):
    with core.subscribers_lock:
        if sender in core.subscribers:
            del core.subscribers[sender]
            core.save_json_locked(settings.SUBSCRIBERS_FILE, core.subscribers)
        return None


def _cmd_set_name(sender: str, args: str):
    if not args:
        return "Invalid format. Use: name/YourName"
    user_name = args.strip().split()[0]
    with core.subscribers_lock:
        if sender not in core.subscribers:
            core.subscribers[sender] = {"alerts": True, "weather": True, "scheduled_daily_forecast": True, "blocked": False}
        core.subscribers[sender]["name"] = user_name
        core.save_json_locked(settings.SUBSCRIBERS_FILE, core.subscribers)
    return None


def _cmd_set_phone(sender: str, args: str):
    usage = "Invalid format. Use: phone/1/number or phone,1,number"
    if not args:
        return usage

    try:
        if "/" in args:
            phone_index, phone_number = args.split("/", 1)
        elif "," in args:
            phone_index, phone_number = args.split(",", 1)
        else:
            raise ValueError()
        phone_index = phone_index.strip()
        phone_number = phone_number.strip()
        if phone_index not in ["1", "2"] or not phone_number:
            raise ValueError()
    except ValueError:
        return usage

    key = f"phone_{phone_index}"
    with core.subscribers_lock:
        if sender not in core.subscribers:
            core.subscribers[sender] = {"alerts": True, "weather": True, "scheduled_daily_forecast": True, "blocked": False}
        core.subscribers[sender][key] = phone_number
        core.save_json_locked(settings.SUBSCRIBERS_FILE, core.subscribers)

    return f"Phone {phone_index} set successfully."


def _parse_address_args(args: str):
    args = args.strip()
    if not args:
        return None

    if "|" in args:
        parts = [p.strip() for p in args.split("|")]
        while len(parts) < 4:
            parts.append("")
        street, city, state, zip_code = parts[:4]
        return {"street": street, "city": city, "state": state, "zip": zip_code}

    if "," in args:
        parts = [p.strip() for p in args.split(",")]
        street = parts[0] if parts else args
        city = parts[1] if len(parts) > 1 else ""
        state_zip = parts[2] if len(parts) > 2 else ""
        state = ""
        zip_code = ""
        if state_zip:
            sz_parts = state_zip.split()
            if sz_parts:
                state = sz_parts[0]
            if len(sz_parts) > 1:
                zip_code = " ".join(sz_parts[1:])
        return {"street": street, "city": city, "state": state, "zip": zip_code}

    return {"street": args, "city": "", "state": "", "zip": ""}


def _cmd_set_address(sender: str, args: str):
    if not args:
        return "Invalid format. Use: address/Street, City, ST ZIP or address,Street, City, ST ZIP"
    address = _parse_address_args(args)
    if not address:
        return "Invalid format. Use: address/Street, City, ST ZIP or address,Street, City, ST ZIP"
    with core.subscribers_lock:
        if sender not in core.subscribers:
            core.subscribers[sender] = {"alerts": True, "weather": True, "scheduled_daily_forecast": True, "blocked": False}
        core.subscribers[sender]["address"] = address
        core.save_json_locked(settings.SUBSCRIBERS_FILE, core.subscribers)
    return "Address set."


def _cmd_toggle_service(sender: str, args: str):
    parts = args.split()
    if len(parts) != 2:
        return "Invalid command. Usage: alerts|weather|forecasts on|off"
    service, status = parts[0].lower(), parts[1].lower()
    if status not in ["on", "off"]:
        return f"Invalid status '{status}'. Use 'on' or 'off'."
    with core.subscribers_lock:
        if not core.subscribers.get(sender):
            return "You must be subscribed first. Send 'subscribe'."
        key_map = {"alerts": "alerts", "weather": "weather", "forecasts": "scheduled_daily_forecast"}
        if service not in key_map:
            return f"Invalid service '{service}'."
        core.subscribers[sender][key_map[service]] = status == "on"
        core.save_json_locked(settings.SUBSCRIBERS_FILE, core.subscribers)
    return None


def _cmd_get_status(sender: str, args: str):
    with core.subscribers_lock:
        sub_data = core.subscribers.get(sender)
        if not sub_data:
            return "You are not subscribed."
        name_str = f"Name: {sub_data.get('name')} | " if sub_data.get("name") else ""
        tags_list = sub_data.get("tags", [])
        tags_str = f" | Tags: {', '.join(tags_list)}" if tags_list else ""
        return (
            f"{name_str}Alerts: {'on' if sub_data.get('alerts') else 'off'} | "
            f"Weather: {'on' if sub_data.get('weather') else 'off'} | "
            f"Forecasts: {'on' if sub_data.get('scheduled_daily_forecast') else 'off'}"
            f"{tags_str}"
        )


def _cmd_send_email(sender: str, args: str):
    with core.subscribers_lock:
        sender_data = core.subscribers.get(sender)
        if not sender_data or not sender_data.get("email_send", False):
            return "You are not authorized to send emails."

    if "/" in args:
        parts = args.split("/", 2)
    else:
        parts = [p.strip() for p in args.split(",", 2)] if "," in args else []
    if len(parts) != 3:
        return "Invalid email format. Use: email/to@addr.com/subject/body or email,to@addr.com,subject,body"
    recipient, subject, body = [p.strip() for p in parts]
    if not (recipient and subject and body):
        return "Invalid email format. All parts are required."
    truncated = False
    if settings.MAX_EMAIL_BODY_LEN > 0 and len(body) > settings.MAX_EMAIL_BODY_LEN:
        body = body[: settings.MAX_EMAIL_BODY_LEN]
        truncated = True
    logging.info(f"Queueing email from {sender} to {recipient}")
    task = {"recipient": recipient, "subject": subject, "body": body, "sender_node": sender}
    queue_email_task(task)
    if truncated:
        return f"Message truncated to {settings.MAX_EMAIL_BODY_LEN} characters."
    return None


def _cmd_tagsend(sender: str, args: str):
    cleanup_expired_temp_groups()

    sender_data = _get_sender_subscriber_record(sender)
    sender_name = sender_data.get("name", sender)
    can_send_static_tags = _flag_enabled(sender_data.get("node_tag_send", False))

    with core.subscribers_lock:
        blocked_map = {
            node_id: bool(sub_data.get("blocked", False))
            for node_id, sub_data in core.subscribers.items()
        }

    try:
        if "/" in args:
            tags_str, message = args.split("/", 1)
        elif "," in args:
            tags_str, message = args.split(",", 1)
        else:
            raise ValueError()
        if not tags_str or not message:
            raise ValueError()
        target_tags = []
        for raw_tag in tags_str.split():
            tag = _normalize_channel_name(raw_tag)
            if not tag or not _is_valid_channel_name(tag):
                raise ValueError()
            target_tags.append(tag)
        target_tags = list(dict.fromkeys(target_tags))
        if not target_tags:
            raise ValueError()
    except ValueError:
        return "Invalid format. Use: tagsend/tag1 tag2.../message or tagsend,tag1 tag2...,message"

    temp_tags = []
    static_tags = []
    for tag in target_tags:
        if _is_reserved_channel_name(tag) or _is_known_permanent_tag(tag):
            static_tags.append(tag)
        elif _is_temp_group_name(tag):
            temp_tags.append(tag)
        else:
            static_tags.append(tag)

    if static_tags and not can_send_static_tags:
        return "You are not authorized to use the tagsend command."

    recipient_ids = set()
    if static_tags:
        with core.subscribers_lock:
            for node_id, sub_data in core.subscribers.items():
                if sub_data.get("blocked", False):
                    continue
                if any(tag in sub_data.get("tags", []) for tag in static_tags):
                    recipient_ids.add(node_id)

    locked_temp_tags = []
    for temp_tag in temp_tags:
        group = gb_db.get_temp_group(temp_tag)
        if not group:
            continue
        if group.get("locked", False):
            locked_temp_tags.append(temp_tag)
            continue
        gb_db.touch_temp_group(temp_tag)
        for member_id in group.get("members", []):
            if not member_id:
                continue
            if blocked_map.get(member_id, False):
                continue
            recipient_ids.add(member_id)

    if locked_temp_tags and not recipient_ids:
        return f"Temporary group(s) locked: {', '.join(sorted(locked_temp_tags))}. Use tagopen to re-enable."

    if not recipient_ids:
        return f"No users found with tags: {', '.join(target_tags)}"

    formatted_message = f"[{', '.join(target_tags)}] {sender_name}\n{message}"
    primary_tag = target_tags[0] if target_tags else "TAG"
    if isinstance(message, str) and message.startswith("\x07"):
        log_text = "\x07@" + primary_tag + " " + message[1:]
    else:
        log_text = f"@{primary_tag} {message}"
    core.log_channel_message(sender, log_text, is_dm=False)
    for recipient_id in recipient_ids:
        send_meshtastic_message(
            formatted_message,
            destinationId=recipient_id,
            suppress_log=True,
            priority=True,
        )
    if locked_temp_tags:
        return f"Message sent. Skipped locked temporary group(s): {', '.join(sorted(locked_temp_tags))}."
    return None


def _cmd_help(sender: str, args: str) -> dict[str, Any]:
    help_lines = [
        "help",
        "?",
        "hello|hi",
        "subscribe",
        "unsubscribe",
        "status",
        "wx",
        "alerts on|off",
        "weather on|off",
        "forecasts on|off",
        "name/<name>",
        "phone/1|2/<number>",
        "address/<addr>",
        "email/to/subj/body",
        "tagsend/<tags>/<msg>",
        "tagin/<TAG>",
        "tagout",
        "tagshut/<GROUP> (admin)",
        "tagopen/<GROUP> (admin)",
        "tagkill/<GROUP> (admin)",
        "active",
        "alertstatus",
        "block/<email> (admin)",
        "unblock/<email> (admin)",
        "SOS | SOSP | SOSF | SOSM [msg]",
        "CLEAR | CANCEL | SAFE",
        "ACK | RESPONDING",
        "Y/YES/OK (check-in)",
    ]
    prefix_bytes = _utf8_len(f"{core.PREFIX_BOT_RESPONSE} ")
    max_bytes = max(20, settings.MAX_MESH_TEXT_LEN - prefix_bytes)
    chunks = _chunk_lines_by_bytes(help_lines, max_bytes)
    return {"responses": chunks}


def _cmd_sos_status(sender: str, args: str):
    with core.sos_log_lock:
        active_sos_events = gb_db.load_active_sos_logs() or []

    if not active_sos_events:
        return "No active SOS alerts at this time."

    response_parts = ["ACTIVE ALERTS:"]
    with core.subscribers_lock:
        for i, sos in enumerate(active_sos_events, 1):
            sender_name = core.subscribers.get(sos["node_id"], {}).get("name", sos["node_id"])
            responding_names = [
                core.subscribers.get(r_id, {}).get("name", r_id) for r_id in sos.get("responding_list", [])
            ]
            responding_str = ", ".join(responding_names) if responding_names else "None"
            response_parts.append(f"{i}. {sos['sos_type']} from {sender_name} (Responding: {responding_str})")

    return "\n".join(response_parts)


def _cmd_block_email(sender: str, args: str):
    if not is_admin(sender):
        return "Access Denied."

    blocklist_path = settings.EMAIL_BLOCKLIST_FILE

    if not args:
        blocked_emails = core.load_json(blocklist_path) or []
        if not blocked_emails:
            return "Email blocklist is empty."
        return "Blocked:\n" + "\n".join(blocked_emails)

    email_to_block = args.strip().lower()
    with core.file_lock(blocklist_path + ".lock"):
        blocked_emails = core.load_json(blocklist_path) or []
        if email_to_block not in blocked_emails:
            blocked_emails.append(email_to_block)
            core.save_json(blocklist_path, blocked_emails)
            return f"Blocked: {email_to_block}"
        return f"{email_to_block} is already blocked."


def _cmd_unblock_email(sender: str, args: str):
    if not is_admin(sender):
        return "Access Denied."

    if not args:
        return "Usage: unblock/email@address.com"

    blocklist_path = settings.EMAIL_BLOCKLIST_FILE
    email_to_unblock = args.strip().lower()

    with core.file_lock(blocklist_path + ".lock"):
        blocked_emails = core.load_json(blocklist_path) or []
        if email_to_unblock in blocked_emails:
            blocked_emails.remove(email_to_unblock)
            core.save_json(blocklist_path, blocked_emails)
            return f"Unblocked: {email_to_unblock}"
        return f"{email_to_unblock} was not on the blocklist."


def _cmd_tagin(sender: str, args: str):
    cleanup_expired_temp_groups()

    tag_to_join = _normalize_channel_name(args)
    if not tag_to_join:
        return "Usage: tagin/TAGNAME"
    if not _is_valid_channel_name(tag_to_join):
        return "Invalid group name. Use 2-32 chars: A-Z, 0-9, _ or -."

    use_permanent_tag_logic = _is_reserved_channel_name(tag_to_join) or _is_known_permanent_tag(tag_to_join)

    if use_permanent_tag_logic:
        with core.subscribers_lock:
            user_tags = [str(t).upper() for t in core.subscribers.get(sender, {}).get("tags", []) if str(t).strip()]
            if tag_to_join not in user_tags:
                return f"You do not have the '{tag_to_join}' tag. Cannot join channel."
    else:
        if _is_temp_group_locked(tag_to_join):
            return f"Temporary group {tag_to_join} is locked. Ask an admin to run tagopen/{tag_to_join}."
        gb_db.add_temp_group_member(tag_to_join, sender)

    with core.node_statuses_lock:
        node_status = gb_db.get_node_status(sender) or {}
        node_status["active_tag_channel"] = tag_to_join
        gb_db.upsert_node_status(sender, node_status)

    if not use_permanent_tag_logic:
        ttl_days = _get_temp_group_ttl_days()
        return (
            f"You are now transmitting to temporary group {tag_to_join}. "
            f"Send 'tagout' to exit. Group expires after {ttl_days} idle day(s)."
        )

    return f"You are now transmitting to {tag_to_join} tagged users. Send 'tagout' to exit."


def _cmd_tagout(sender: str, args: str):
    cleanup_expired_temp_groups()

    active_tag_channel = None
    with core.node_statuses_lock:
        node_status = gb_db.get_node_status(sender) or {}
        active_tag_channel = node_status.get("active_tag_channel")
        if active_tag_channel:
            node_status.pop("active_tag_channel", None)
            if not node_status:
                gb_db.delete_node_status(sender)
            else:
                gb_db.upsert_node_status(sender, node_status)

    if active_tag_channel:
        if _is_temp_group_name(active_tag_channel):
            gb_db.remove_temp_group_member(active_tag_channel, sender)
        return "You have exited the tag."

    return "You are not in a tag."


def _cmd_tagshut(sender: str, args: str):
    cleanup_expired_temp_groups()
    if not is_admin(sender):
        return "Access Denied."
    group_name = _normalize_channel_name(args)
    if not group_name:
        return "Usage: tagshut/GROUPNAME"
    if not _is_temp_group_name(group_name):
        return f"Temporary group '{group_name}' not found."
    gb_db.set_temp_group_locked(group_name, True)
    return f"Temporary group {group_name} is now locked."


def _cmd_tagopen(sender: str, args: str):
    cleanup_expired_temp_groups()
    if not is_admin(sender):
        return "Access Denied."
    group_name = _normalize_channel_name(args)
    if not group_name:
        return "Usage: tagopen/GROUPNAME"
    if not _is_temp_group_name(group_name):
        return f"Temporary group '{group_name}' not found."
    gb_db.set_temp_group_locked(group_name, False)
    return f"Temporary group {group_name} is now open."


def _cmd_tagkill(sender: str, args: str):
    cleanup_expired_temp_groups()
    if not is_admin(sender):
        return "Access Denied."
    group_name = _normalize_channel_name(args)
    if not group_name:
        return "Usage: tagkill/GROUPNAME"
    if not _is_temp_group_name(group_name):
        return f"Temporary group '{group_name}' not found."

    with core.node_statuses_lock:
        node_statuses = gb_db.load_node_statuses_dict() or {}
        updated = False
        for node_id, status in node_statuses.items():
            if status.get("active_tag_channel") == group_name:
                status = dict(status)
                status.pop("active_tag_channel", None)
                node_statuses[node_id] = status
                updated = True
        if updated:
            gb_db.replace_node_statuses(node_statuses)

    gb_db.delete_temp_group(group_name)
    return f"Temporary group {group_name} has been deleted."


COMMAND_HANDLERS: dict[str, Callable[[str, str], Any]] = {
    "help": _cmd_help,
    "hello": _cmd_hello,
    "hi": _cmd_hello,
    "subscribe": _cmd_subscribe,
    "unsubscribe": _cmd_unsubscribe,
    "name": _cmd_set_name,
    "phone": _cmd_set_phone,
    "address": _cmd_set_address,
    "alerts": _cmd_toggle_service,
    "weather": _cmd_toggle_service,
    "forecasts": _cmd_toggle_service,
    "status": _cmd_get_status,
    "email": _cmd_send_email,
    "tagsend": _cmd_tagsend,
    "wx": _cmd_get_forecast,
    "?": _cmd_help,
    "active": _cmd_sos_status,
    "alertstatus": _cmd_sos_status,
    "block": _cmd_block_email,
    "unblock": _cmd_unblock_email,
    "tagin": _cmd_tagin,
    "tagout": _cmd_tagout,
    "tagshut": _cmd_tagshut,
    "tagopen": _cmd_tagopen,
    "tagkill": _cmd_tagkill,
}


def handle_meshtastic_command(sender: str, command_text: str) -> None:
    command_word, args = parse_command_text(command_text)
    if command_word in ["alerts", "weather", "forecasts"]:
        args = f"{command_word} {args}".strip()
    handler = COMMAND_HANDLERS.get(command_word)
    if handler:
        logging.info(f"Processing command '{command_word}' with args '{args}' for sender {sender}")
        result = handler(sender, args)
        if result is not None:
            responses = None
            add_bot_prefix = True
            if isinstance(result, dict):
                add_bot_prefix = not result.get("no_prefix")
                responses = result.get("responses")
                if responses is None:
                    responses = [result.get("response")]
            else:
                responses = [result]

            for response in responses:
                if response:
                    full_response = f"{core.PREFIX_BOT_RESPONSE} {response}" if add_bot_prefix else response
                    send_meshtastic_message(full_response, destinationId=sender, wantAck=True, priority=True)


def get_command_handler(text: str) -> Tuple[Callable[..., Any], Tuple[Any, ...]]:
    text_upper = text.upper()

    sos_command = next((cmd for cmd in core.SOS_COMMANDS if text_upper.startswith(cmd)), None)
    if sos_command:
        return handle_sos_alert, (sos_command, text[len(sos_command) :].strip())

    command_map = {
        **{cmd: (handle_sos_clear, ()) for cmd in core.CLEAR_COMMANDS},
        **{cmd: (handle_sos_action_initial, (text_upper,)) for cmd in core.ACK_COMMANDS.union(core.RESPONDING_COMMANDS)},
        **{cmd: (handle_sos_checkin_response, ()) for cmd in core.CHECKIN_RESPONSES},
    }

    command_word = text_upper.split()[0]
    if command_word in command_map:
        return command_map[command_word]

    return handle_meshtastic_command, (text,)


def command_processor_worker() -> None:
    logging.info("Command processor thread started.")
    while True:
        try:
            queue_item = core.command_queue.get()
            queued_at = None
            if isinstance(queue_item, dict):
                sender = queue_item.get("sender")
                text = queue_item.get("text")
                queued_at = queue_item.get("queued_at")
            elif isinstance(queue_item, (tuple, list)):
                if len(queue_item) < 2:
                    logging.warning(f"Invalid command queue item ignored: {queue_item}")
                    continue
                sender, text = queue_item[0], queue_item[1]
                if len(queue_item) >= 3:
                    queued_at = queue_item[2]
            else:
                logging.warning(f"Invalid command queue item ignored: {queue_item}")
                continue
            if sender is None:
                break
            text = str(text or "").strip()
            if not text:
                continue

            current_time = time.time()
            if isinstance(queued_at, (int, float)):
                queue_wait_ms = max(0.0, (current_time - float(queued_at)) * 1000.0)
                core.record_latency_sample("command_queue_wait_ms", queue_wait_ms)
                if queue_wait_ms >= core.COMMAND_QUEUE_WAIT_WARN_MS:
                    logging.warning(f"Command queue wait high ({queue_wait_ms:.1f}ms) for sender {sender}.")

            process_start = time.perf_counter()
            with core.user_last_command_time_lock:
                if current_time - core.user_last_command_time.get(sender, 0) < core.COMMAND_COOLDOWN_SECONDS:
                    logging.warning(f"User {sender} rate-limited. Ignoring command: '{text}'")
                    continue
                core.user_last_command_time[sender] = current_time

            if core.COMMAND_BURST_LIMIT > 0 and core.COMMAND_BURST_WINDOW_SECONDS > 0:
                with core.user_command_history_lock:
                    history = core.user_command_history.get(sender)
                    if history is None:
                        history = []
                        core.user_command_history[sender] = history
                    cutoff = current_time - core.COMMAND_BURST_WINDOW_SECONDS
                    history[:] = [ts for ts in history if ts >= cutoff]
                    if len(history) >= core.COMMAND_BURST_LIMIT:
                        logging.warning(
                            f"User {sender} burst rate-limited. Ignoring command: '{text}'"
                        )
                        continue
                    history.append(current_time)

            with core.user_interaction_state_lock:
                if core.user_interaction_state.get(sender) == "awaiting_sos_choice":
                    parts = text.upper().split()
                    cmd_word, cmd_arg = parts[0], parts[1] if len(parts) > 1 else None
                    if cmd_word in core.ACK_COMMANDS.union(core.RESPONDING_COMMANDS) and cmd_arg and cmd_arg.isdigit():
                        del core.user_interaction_state[sender]
                        handle_sos_choice(sender, cmd_word, int(cmd_arg))
                        continue

            handler, args = get_command_handler(text)
            handler(sender, *args)
            handler_ms = max(0.0, (time.perf_counter() - process_start) * 1000.0)
            core.record_latency_sample("command_handler_ms", handler_ms)
            if handler_ms >= core.COMMAND_HANDLER_WARN_MS:
                logging.warning(f"Command handler slow ({handler_ms:.1f}ms) for sender {sender}.")

        except Exception as e:
            logging.error(f"Error in command processor thread: {e}", exc_info=True)
            core.record_runtime_error("command_processor_worker", str(e))


def _resolve_auto_backup_dir() -> str:
    base_dir = getattr(settings, "BASE_DIR", "/opt/GuardianBridge")
    return os.path.realpath(
        os.path.abspath(getattr(settings, "AUTO_BACKUP_DIR", os.path.join(base_dir, "AutoBackUp")))
    )


def _path_is_within(path: str, root: str) -> bool:
    path_real = os.path.realpath(os.path.abspath(path))
    root_real = os.path.realpath(os.path.abspath(root))
    try:
        common = os.path.commonpath([path_real, root_real])
    except ValueError:
        return False
    return common == root_real


def _run_local_script(script_filename: str, timeout_seconds: int = 600) -> str:
    base_dir = getattr(settings, "BASE_DIR", "/opt/GuardianBridge")
    script_path = os.path.join(base_dir, script_filename)
    if not os.path.isfile(script_path):
        raise FileNotFoundError(f"Script not found: {script_path}")

    python_exec = sys.executable or "python3"
    result = subprocess.run(
        [python_exec, script_path],
        capture_output=True,
        text=True,
        timeout=max(1, int(timeout_seconds)),
        check=False,
    )
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    output = "\n".join(part for part in [stdout, stderr] if part).strip()
    if result.returncode != 0:
        raise RuntimeError(
            f"{script_filename} failed (exit={result.returncode}): {(output or 'no output')[:800]}"
        )
    return output[:1200]


class CommandPayloadError(ValueError):
    def __init__(self, reason: str, details: Optional[dict[str, Any]] = None):
        super().__init__(reason)
        self.reason = str(reason or "Invalid command payload.")
        self.details = details if isinstance(details, dict) else {}


def _raise_command_payload(reason: str, details: Optional[dict[str, Any]] = None) -> None:
    raise CommandPayloadError(reason, details=details)


def _execute_command_payload(command_data: dict[str, Any], source_file: str) -> tuple[str, dict[str, Any]]:
    cmd = command_data.get("command")
    processed_details: dict[str, Any] = {"command": cmd, "source_file": source_file}

    if cmd == "relay":
        recipients, text = command_data.get("recipients", []), command_data.get("text")
        if not all([recipients, text]):
            _raise_command_payload("Missing 'recipients' or 'text' for relay command.", details={"command": cmd})
        for r_id in recipients:
            send_meshtastic_message(f"{core.PREFIX_EMAIL} {text}", destinationId=r_id, wantAck=True)
        processed_details["recipient_count"] = len(recipients)
        return "processed", processed_details

    if cmd == "broadcast":
        text = command_data.get("text")
        if text is None:
            _raise_command_payload("Missing 'text' for broadcast command.", details={"command": cmd})
        send_meshtastic_message(text)
        return "processed", processed_details

    if cmd == "dm":
        dest_id, r_name, text = (
            command_data.get("destinationId"),
            command_data.get("recipient"),
            command_data.get("text"),
        )
        if not all([dest_id, r_name, text]):
            _raise_command_payload("Missing fields for dm command.", details={"command": cmd})
        send_meshtastic_message(
            text=text,
            destinationId=dest_id,
            wantAck=True,
            text_for_log=f"@{r_name} {text}",
            priority=True,
        )
        processed_details["destinationId"] = dest_id
        return "processed", processed_details

    if cmd == "broadcast_subscribers":
        text = command_data.get("text")
        if text is None or not str(text).strip():
            _raise_command_payload("Missing 'text' for broadcast_subscribers command.", details={"command": cmd})
        if isinstance(text, str) and text.startswith("\x07"):
            log_text = "\x07@all " + text[1:]
        else:
            log_text = f"@all {text}"
        core.log_channel_message("GATEWAY", log_text, is_dm=False)

        subscribers = gb_db.load_subscribers_dict() or {}
        recipient_count = 0
        if not subscribers:
            logging.warning("broadcast_subscribers: no subscribers found.")
        for node_id, data in subscribers.items():
            if data.get("blocked", False):
                continue
            send_meshtastic_message(
                text=text,
                destinationId=node_id,
                wantAck=True,
                suppress_log=True,
                priority=True,
            )
            recipient_count += 1
        processed_details["recipient_count"] = recipient_count
        return "processed", processed_details

    if cmd == "tagsend":
        tags, text = command_data.get("tags", []), command_data.get("text")
        if not all([tags, text]):
            _raise_command_payload("Missing 'tags' or 'text' for tagsend command.", details={"command": cmd})
        target_tags = [t.strip().upper() for t in tags.split(",")] if isinstance(tags, str) else tags
        target_tags = [t for t in target_tags if isinstance(t, str) and t.strip()]
        primary_tag = target_tags[0] if target_tags else "TAG"
        text_body = str(text)
        has_bell = text_body.startswith("\x07")
        if has_bell:
            text_body = text_body[1:]
        recipient_text = f"[{primary_tag}] {text_body}"
        if has_bell:
            recipient_text = "\x07" + recipient_text
        if has_bell:
            log_text = "\x07@" + primary_tag + " " + text_body
        else:
            log_text = f"@{primary_tag} {text_body}"
        core.log_channel_message("GATEWAY", log_text, is_dm=False)
        subscribers = gb_db.load_subscribers_dict() or {}
        recipient_ids = {
            node_id
            for node_id, data in subscribers.items()
            if not data.get("blocked", False) and any(t in data.get("tags", []) for t in target_tags)
        }
        for temp_tag in target_tags:
            group = gb_db.get_temp_group(temp_tag)
            if not group:
                continue
            if group.get("locked", False):
                logging.info(f"Skipping locked temporary group {temp_tag} for queued tagsend command.")
                continue
            gb_db.touch_temp_group(temp_tag)
            for member_id in group.get("members", []):
                sub_data = subscribers.get(member_id, {})
                if sub_data.get("blocked", False):
                    continue
                recipient_ids.add(member_id)
        if recipient_ids:
            logging.info(f"Tag-based send to {len(recipient_ids)} recipients for tags: {target_tags}")
            for r_id in recipient_ids:
                send_meshtastic_message(
                    recipient_text,
                    destinationId=r_id,
                    wantAck=True,
                    suppress_log=True,
                    priority=True,
                )
            processed_details["recipient_count"] = len(recipient_ids)
        else:
            logging.warning(f"No subscribers found for tags {target_tags}. Message not sent.")
            processed_details["recipient_count"] = 0
        return "processed", processed_details

    if cmd == "admin_clear_sos":
        node_id = command_data.get("node_id")
        if node_id:
            logging.info(f"Processing admin request to clear SOS for node: {node_id}")
            handle_sos_clear(node_id, admin_clear=True)
            processed_details["node_id"] = node_id
            return "processed", processed_details
        _raise_command_payload("Missing 'node_id' for admin_clear_sos command.", details={"command": cmd})

    if cmd == "run_weather_fetcher":
        output_preview = _run_local_script("weather_fetcher.py", timeout_seconds=600)
        processed_details["output_preview"] = output_preview
        logging.info("Processed queued weather fetcher command.")
        return "processed", processed_details

    if cmd == "run_email_processor":
        output_preview = _run_local_script("email_processor.py", timeout_seconds=600)
        processed_details["output_preview"] = output_preview
        logging.info("Processed queued email processor command.")
        return "processed", processed_details

    if cmd == "maintenance_backup_db":
        auto_backup_dir = _resolve_auto_backup_dir()
        os.makedirs(auto_backup_dir, exist_ok=True)
        backup_path = gb_db.create_db_backup(auto_backup_dir)
        processed_details["backup_path"] = backup_path
        logging.info(f"Processed queued DB backup command: {backup_path}")
        return "processed", processed_details

    if cmd == "maintenance_restore_db":
        raw_source_path = str(command_data.get("source_db_path") or "").strip()
        if not raw_source_path:
            _raise_command_payload("Missing 'source_db_path' for maintenance_restore_db command.", details={"command": cmd})
        source_path = os.path.realpath(os.path.abspath(raw_source_path))
        auto_backup_dir = _resolve_auto_backup_dir()
        if not _path_is_within(source_path, auto_backup_dir):
            _raise_command_payload(
                "source_db_path is outside AutoBackUp directory.",
                details={"command": cmd, "source_db_path": source_path},
            )
        if not os.path.isfile(source_path):
            _raise_command_payload(
                "source_db_path does not exist.",
                details={"command": cmd, "source_db_path": source_path},
            )
        if not source_path.lower().endswith(".db"):
            _raise_command_payload(
                "source_db_path must be a .db file.",
                details={"command": cmd, "source_db_path": source_path},
            )

        os.makedirs(auto_backup_dir, exist_ok=True)
        safety_backup = gb_db.create_db_backup(auto_backup_dir, filename_prefix="guardianbridge_db_pre_restore")
        gb_db.restore_database_from_backup(source_path)
        processed_details["source_db_path"] = source_path
        processed_details["safety_backup_path"] = safety_backup

        cleanup_source = bool(command_data.get("cleanup_source"))
        source_name = os.path.basename(source_path)
        if cleanup_source and source_name.startswith("uploaded_restore_"):
            try:
                os.remove(source_path)
                processed_details["source_deleted"] = True
            except OSError as remove_error:
                processed_details["source_deleted"] = False
                processed_details["source_delete_error"] = str(remove_error)
        logging.info(f"Processed queued DB restore command from: {source_name}")
        return "processed", processed_details

    if cmd == "maintenance_vacuum_db":
        gb_db.vacuum_database()
        logging.info("Processed queued DB vacuum command.")
        return "processed", processed_details

    if command_data.get("sender") and cmd:
        sender_id = command_data.get("sender")
        command_text = command_data.get("command")
        if sender_id and isinstance(command_text, str) and command_text.strip():
            logging.info(f"Processing queued command from {sender_id}: '{command_text}'")
            core.enqueue_command(sender_id, command_text)
            processed_details["sender"] = sender_id
            return "processed", processed_details
        _raise_command_payload("Missing 'sender' or 'command' for queued command.", details={"command": cmd})

    logging.warning(f"Unknown queued command '{cmd}' from {source_file}. Ignoring.")
    return "ignored", processed_details


def _compute_command_retry_delay(attempt_count: int) -> int:
    base_seconds = max(1, int(getattr(settings, "COMMAND_JOB_RETRY_BASE_SECONDS", 2)))
    max_seconds = max(base_seconds, int(getattr(settings, "COMMAND_JOB_RETRY_MAX_SECONDS", 300)))
    exponent = max(0, int(attempt_count) - 1)
    delay = min(max_seconds, base_seconds * (2 ** exponent))
    jitter = random.randint(0, max(1, delay // 3))
    return min(max_seconds, delay + jitter)


def process_command_jobs(max_jobs: Optional[int] = None) -> int:
    lease_seconds = max(5, int(getattr(settings, "COMMAND_JOB_LEASE_SECONDS", 30)))
    default_batch = max(1, int(getattr(settings, "COMMAND_JOB_BATCH_SIZE", 20)))
    max_to_process = max(1, int(max_jobs if max_jobs is not None else default_batch))
    processed_count = 0
    had_error = False

    for _ in range(max_to_process):
        job = gb_db.claim_next_command_job(lease_seconds=lease_seconds)
        if not job:
            break

        job_id = int(job.get("id") or 0)
        command_id = str(job.get("command_id") or "").strip() or f"job:{job_id}"
        source_file = str(job.get("source_file") or "").strip() or f"db-job:{job_id}"
        attempt_count = int(job.get("attempt_count") or 0)
        max_attempts = max(1, int(job.get("max_attempts") or 1))
        payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
        processed_count += 1

        try:
            status, details = _execute_command_payload(payload, source_file)
            details["job_id"] = job_id
            details["attempt_count"] = attempt_count
            gb_db.mark_command_job_succeeded(job_id, details=details)
            gb_db.upsert_command_receipt(
                command_id,
                source_file=source_file,
                status=status,
                details=details,
            )
        except CommandPayloadError as payload_error:
            had_error = True
            dead_details = dict(payload_error.details or {})
            dead_details.setdefault("command", payload.get("command"))
            dead_details["job_id"] = job_id
            dead_details["attempt_count"] = attempt_count
            dead_details["max_attempts"] = max_attempts
            dead_details["payload"] = payload
            gb_db.mark_command_job_failed(job_id, error_message=payload_error.reason, details=dead_details)
            gb_db.add_command_dead_letter(command_id, source_file, payload_error.reason, dead_details)
            gb_db.upsert_command_receipt(
                command_id,
                source_file=source_file,
                status="dead-letter",
                details=dead_details,
            )
        except Exception as e:
            had_error = True
            retry_details = {
                "command": payload.get("command"),
                "job_id": job_id,
                "attempt_count": attempt_count,
                "max_attempts": max_attempts,
                "payload": payload,
            }
            if attempt_count >= max_attempts:
                reason = "Unhandled exception during processing."
                retry_details["exception"] = str(e)
                gb_db.mark_command_job_failed(job_id, error_message=str(e), details=retry_details)
                gb_db.add_command_dead_letter(command_id, source_file, reason, retry_details)
                gb_db.upsert_command_receipt(
                    command_id,
                    source_file=source_file,
                    status="dead-letter",
                    details=retry_details,
                )
                logging.error(
                    f"Command job exhausted retries (command_id={command_id}, attempts={attempt_count}/{max_attempts}): {e}",
                    exc_info=True,
                )
            else:
                retry_delay = _compute_command_retry_delay(attempt_count)
                retry_details["retry_delay_seconds"] = retry_delay
                retry_details["exception"] = str(e)
                gb_db.mark_command_job_retry(
                    job_id,
                    retry_delay_seconds=retry_delay,
                    error_message=str(e),
                    details=retry_details,
                )
                gb_db.upsert_command_receipt(
                    command_id,
                    source_file=source_file,
                    status="retrying",
                    details=retry_details,
                )
                logging.warning(
                    f"Command job failed, retry scheduled (command_id={command_id}, attempts={attempt_count}/{max_attempts}, delay={retry_delay}s): {e}"
                )
            core.record_runtime_error("process_command_jobs", str(e))

    if not had_error:
        core.clear_runtime_error("process_command_jobs")

    return processed_count
