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

# email_processor.py

import os
import json
import logging
import time
import re
from datetime import datetime, timezone
import smtplib
from email.mime.text import MIMEText
import sys
import settings
from pathlib import Path
from tzlocal import get_localzone_name
from imap_tools import MailBox, AND
from bs4 import BeautifulSoup
import pytz
from dateutil.tz import gettz

from contextlib import contextmanager
import gb_db
# Logging setup
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, "INFO"), format="%(asctime)s [%(levelname)s] %(message)s")

VALID_COMMANDS = {"subscribe", "unsubscribe", "alerts on", "alerts off", "weather on", "weather off", "forecasts on", "forecasts off", "status", "help", "?", "name"}

def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)

def write_json_atomic(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    temp_path = f"{path}.{os.getpid()}.tmp"
    with open(temp_path, "w") as f:
        json.dump(data, f)
    os.replace(temp_path, path)


def enqueue_dispatcher_command(command_data, source_file):
    max_attempts = max(1, int(getattr(settings, "COMMAND_JOB_MAX_ATTEMPTS", 5)))
    return gb_db.enqueue_command_job(
        command_data=command_data,
        source_file=source_file,
        max_attempts=max_attempts,
    )

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

def acquire_instance_lock(lock_path, max_age_seconds=1800):
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

def release_instance_lock(lock_path):
    try:
        os.remove(lock_path)
    except OSError:
        pass

def load_rate_limit_state():
    state = load_json(settings.EMAIL_RATE_LIMIT_FILE) or {}
    if not isinstance(state, dict):
        return {}
    return state

def prune_rate_limit_state(state, now_ts, window_seconds):
    if window_seconds <= 0:
        return state
    for sender, stamps in list(state.items()):
        if not isinstance(stamps, list):
            state.pop(sender, None)
            continue
        cleaned = [ts for ts in stamps if isinstance(ts, (int, float)) and (now_ts - ts) < window_seconds]
        if cleaned:
            state[sender] = cleaned
        else:
            state.pop(sender, None)
    return state

def clean_forwarded_body(body):
    master_separator_pattern = re.compile(
        r"sent the following message:|-----Original Message-----|^\s*>?\s*On .* wrote:\s*$",
        re.IGNORECASE | re.MULTILINE
    )
    parts = master_separator_pattern.split(body, maxsplit=1)
    return parts[0].strip()

def find_and_authorize_broadcast_sender(sender_email, subscribers):
    for node_id, data in subscribers.items():
        if data.get('email', '').lower() == sender_email.lower():
            if data.get('emailbroadcast', False):
                return data.get('name', 'Unknown User')
    return None

def send_feedback_email(recipient, subject, body):
    try:
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(settings.EMAIL_USER, settings.EMAIL_PASS)
            email_msg = MIMEText(body)
            email_msg["Subject"] = subject
            email_msg["From"] = f"GuardianBridge <{settings.EMAIL_USER}>"
            email_msg["To"] = recipient
            smtp.send_message(email_msg)
            logging.info(f"Sent feedback email to {recipient}")
    except Exception as e:
        logging.error(f"Failed to send feedback email to {recipient}: {e}", exc_info=True)

def find_recipients_in_subject(subject, subscribers):
    resolved_node_ids = set()
    found_ids = re.findall(r'(![a-fA-F0-9]{8})', subject)
    for node_id in found_ids: resolved_node_ids.add(node_id)
    for node_id, data in subscribers.items():
        name = data.get("name")
        if name and name.lower() in subject.lower():
            resolved_node_ids.add(node_id)
    return list(resolved_node_ids)

def process_incoming_emails():
    subscribers = gb_db.load_subscribers_dict() or {}
    rate_limit_enabled = settings.EMAIL_RATE_LIMIT_MAX > 0 and settings.EMAIL_RATE_LIMIT_WINDOW_SECONDS > 0
    rate_limit_state = {}
    rate_limit_dirty = False
    if rate_limit_enabled:
        now_ts = time.time()
        rate_limit_state = prune_rate_limit_state(load_rate_limit_state(), now_ts, settings.EMAIL_RATE_LIMIT_WINDOW_SECONDS)
        rate_limit_dirty = True
    
    # --- NEW: Load the email blocklist ---
    email_blocklist = load_json(settings.EMAIL_BLOCKLIST_FILE) or []
    email_blocklist = {email.lower() for email in email_blocklist} # Convert to a set for faster lookups
    
    processed_uids = []
    try:
        with MailBox(settings.IMAP_SERVER, port=settings.IMAP_PORT).login(settings.EMAIL_USER, settings.EMAIL_PASS, initial_folder="INBOX") as mailbox:
            for msg in mailbox.fetch(AND(seen=False)):
                try:
                    sender_email = (msg.from_ or "").strip()
                    if not sender_email:
                        logging.warning(f"Skipping email with missing sender. UID: {msg.uid}")
                        processed_uids.append(msg.uid)
                        continue
                    sender_key = sender_email.lower().strip()
                    
                    # --- NEW: Check if the sender is on the blocklist ---
                    if sender_key in email_blocklist:
                        logging.warning(f"Ignoring email from blocked sender: {sender_email}")
                        processed_uids.append(msg.uid)
                        continue # Skip to the next message

                    if rate_limit_enabled and sender_key:
                        now_ts = time.time()
                        sender_timestamps = rate_limit_state.get(sender_key, [])
                        if not isinstance(sender_timestamps, list):
                            sender_timestamps = []
                        sender_timestamps = [
                            ts for ts in sender_timestamps
                            if isinstance(ts, (int, float)) and (now_ts - ts) < settings.EMAIL_RATE_LIMIT_WINDOW_SECONDS
                        ]
                        if len(sender_timestamps) >= settings.EMAIL_RATE_LIMIT_MAX:
                            logging.warning(f"Email rate limit exceeded for {sender_email}. Dropping message.")
                            rate_limit_state[sender_key] = sender_timestamps
                            rate_limit_dirty = True
                            processed_uids.append(msg.uid)
                            continue
                        sender_timestamps.append(now_ts)
                        rate_limit_state[sender_key] = sender_timestamps
                        rate_limit_dirty = True
                        
                    logging.info(f"Processing email from {sender_email}: {msg.subject}")
                    
                    subject_raw = (msg.subject or '').strip()
                    subject_lower = subject_raw.lower()
                    raw_body = msg.text or (BeautifulSoup(msg.html or '', 'html.parser').get_text(separator='\n').strip())
                    
                    if 'broadcast' in subject_lower:
                        sender_name = find_and_authorize_broadcast_sender(sender_email, subscribers)
                        if sender_name:
                            is_alert = subject_lower.startswith('!') or subject_lower.endswith('!')
                            log_msg = f"Authorized broadcast request from {sender_name} ({sender_email})"
                            if is_alert: log_msg += " with alert"
                            logging.info(log_msg)
                            
                            cleaned_body = clean_forwarded_body(raw_body)
                            
                            MAX_PAYLOAD_SIZE = 199
                            DOWNSTREAM_PREFIX_BYTES = 5
                            BELL_CHAR_BYTES = 1 if is_alert else 0
                            effective_max_size = MAX_PAYLOAD_SIZE - DOWNSTREAM_PREFIX_BYTES - BELL_CHAR_BYTES
                            
                            prefix = f"FM {sender_name}:\n"
                            prefix_len = len(prefix.encode('utf-8'))
                            max_body_len = effective_max_size - prefix_len
                            if settings.MAX_EMAIL_BODY_LEN > 0:
                                max_body_len = min(max_body_len, settings.MAX_EMAIL_BODY_LEN)
                            if max_body_len < 0: max_body_len = 0

                            truncated_body = cleaned_body.encode('utf-8')[:max_body_len].decode('utf-8', errors='ignore')
                            
                            message_to_send = prefix + truncated_body
                            if is_alert:
                                message_to_send = "\x07" + message_to_send

                            command_data = {"command": "broadcast", "text": message_to_send, "timestamp": datetime.now(timezone.utc).isoformat()}
                            queue_result = enqueue_dispatcher_command(
                                command_data,
                                source_file=f"email:broadcast:{sanitize_filename(sender_email)}",
                            )
                            logging.info(
                                "Queued broadcast command (job_id=%s, command_id=%s, duplicate=%s).",
                                queue_result.get("job_id"),
                                queue_result.get("command_id"),
                                queue_result.get("status") != "queued",
                            )
                            
                            send_feedback_email(sender_email, "Broadcast Received", "Your broadcast message has been successfully queued for transmission to the network.")
                        else:
                            logging.warning(f"Unauthorized broadcast attempt from {sender_email}")
                            send_feedback_email(sender_email, "Broadcast Failed", "Your email address is not authorized to send broadcast messages via the GuardianBridge.")
                        
                        processed_uids.append(msg.uid)
                        continue

                    if subject_lower.startswith('tag '):
                        sender_name = find_and_authorize_broadcast_sender(sender_email, subscribers)
                        if sender_name:
                            target_tags = [tag.strip().upper() for tag in subject_raw[4:].strip().split()]
                            
                            if not target_tags:
                                logging.warning(f"Tag-based email from {sender_email} received with no specified tags. Ignoring.")
                                processed_uids.append(msg.uid)
                                continue

                            logging.info(f"Processing authorized tag-based relay from {sender_email} for tags: {target_tags}")
                            
                            recipient_ids = set()
                            for node_id, sub_data in subscribers.items():
                                user_tags = [t.upper() for t in sub_data.get('tags', [])]
                                if sub_data.get('blocked', False):
                                    continue
                                if any(tag in user_tags for tag in target_tags) and sub_data.get('email_receive', False):
                                    recipient_ids.add(node_id)

                            if recipient_ids:
                                final_recipients = list(recipient_ids)
                                cleaned_body = clean_forwarded_body(raw_body)
                                
                                header_part = f"{sender_email}\n"
                                max_body_len = 190 - len(header_part)
                                if settings.MAX_EMAIL_BODY_LEN > 0:
                                    max_body_len = min(max_body_len, settings.MAX_EMAIL_BODY_LEN)
                                truncated_body = cleaned_body[:max_body_len]
                                message_to_send = header_part + truncated_body

                                command_data = {"command": "relay", "recipients": final_recipients, "text": message_to_send, "timestamp": datetime.now(timezone.utc).isoformat()}
                                queue_result = enqueue_dispatcher_command(
                                    command_data,
                                    source_file=f"email:tag_relay:{sanitize_filename(sender_email)}",
                                )
                                logging.info(
                                    "Queued tag relay command (job_id=%s, command_id=%s) for %s recipients.",
                                    queue_result.get("job_id"),
                                    queue_result.get("command_id"),
                                    len(final_recipients),
                                )

                                send_feedback_email(sender_email, "Message Relayed to Tagged Group", f"Your message has been queued for transmission to {len(final_recipients)} users with the tags: {', '.join(target_tags)}.")
                            else:
                                logging.warning(f"No authorized recipients found for tags {target_tags} from {sender_email}.")
                                send_feedback_email(sender_email, "Message Relay Failed", f"No authorized users were found for the tags: {', '.join(target_tags)}.")
                        else:
                            logging.warning(f"Unauthorized tag-based relay attempt from {sender_email}")
                            send_feedback_email(sender_email, "Tag-Based Relay Failed", "Your email address is not authorized to send tag-based messages via the GuardianBridge.")
                        
                        processed_uids.append(msg.uid)
                        continue
                    
                    cleaned_body = clean_forwarded_body(raw_body)
                    
                    destination_nodes = []
                    destination_nodes = find_recipients_in_subject(subject_raw, subscribers)
                    if destination_nodes: logging.info(f"Tier 1 SUCCESS: Found recipients in subject: {destination_nodes}")
                    
                    if not destination_nodes:
                        to_header_tuple = msg.headers.get('to')
                        to_header_str = " ".join(to_header_tuple) if to_header_tuple else ""
                        if to_header_str:
                            destination_nodes = re.findall(r'(![a-fA-F0-9]{8})', to_header_str)
                            if destination_nodes: logging.info(f"Tier 2 SUCCESS: Found recipients in 'To' header: {destination_nodes}")

                    if not destination_nodes:
                        watermark_match = re.search(r'\(?(![a-fA-F0-9]{8})\)? sent the following message:', raw_body)
                        if watermark_match:
                            destination_nodes = [watermark_match.group(1)]
                            logging.info(f"Tier 3 SUCCESS: Found recipient from GuardianBridge watermark: {destination_nodes}")

                    if not destination_nodes:
                        body_nodes = re.findall(r'(![a-fA-F0-9]{8})', raw_body)
                        if body_nodes:
                            destination_nodes = [body_nodes[0]]
                            logging.info(f"Tier 4 SUCCESS: Found recipient in email body: {destination_nodes}")
                        
                    if destination_nodes:
                        authorized_recipients = [node_id for node_id in destination_nodes if subscribers.get(node_id, {}).get('email_receive', False)]
                        if not authorized_recipients:
                            logging.warning(f"Email from {sender_email} found recipients {destination_nodes}, but none are authorized. Ignoring.")
                            processed_uids.append(msg.uid)
                            continue

                        final_recipients = authorized_recipients
                        
                        MAX_PAYLOAD_SIZE = 199 
                        DOWNSTREAM_PREFIX_BYTES = 5
                        effective_max_size = MAX_PAYLOAD_SIZE - DOWNSTREAM_PREFIX_BYTES
                        header_part = f"{sender_email}\n"
                        header_length = len(header_part.encode('utf-8'))
                        max_body_len_bytes = effective_max_size - header_length
                        if settings.MAX_EMAIL_BODY_LEN > 0:
                            max_body_len_bytes = min(max_body_len_bytes, settings.MAX_EMAIL_BODY_LEN)

                        if max_body_len_bytes < 0: max_body_len_bytes = 0

                        encoded_body = cleaned_body.encode('utf-8')
                        truncated_body = encoded_body[:max_body_len_bytes].decode('utf-8', errors='ignore')

                        message_to_send = header_part + truncated_body
                        logging.info(f"Constructed message for relay. Length: {len(message_to_send.encode('utf-8'))} bytes.")
                        
                        command_data = {"command": "relay", "recipients": final_recipients, "text": message_to_send, "timestamp": datetime.now(timezone.utc).isoformat()}
                        queue_result = enqueue_dispatcher_command(
                            command_data,
                            source_file=f"email:relay:{sanitize_filename(sender_email)}",
                        )
                        logging.info(
                            "Queued relay command (job_id=%s, command_id=%s) for recipients %s",
                            queue_result.get("job_id"),
                            queue_result.get("command_id"),
                            final_recipients,
                        )
                    else:
                        sender_id = f"email_{sanitize_filename(sender_email)}"
                        raw_body_stripped = raw_body.strip()
                        command_line = raw_body_stripped.splitlines()[0].lower().strip() if raw_body_stripped else ''
                        if command_line in VALID_COMMANDS:
                            command_data = { "sender": sender_id, "command": command_line, "timestamp": datetime.now(timezone.utc).isoformat() }
                            queue_result = enqueue_dispatcher_command(
                                command_data,
                                source_file=f"email:command:{sanitize_filename(sender_email)}",
                            )
                            logging.info(
                                "Queued standard command for %s: '%s' (job_id=%s, command_id=%s)",
                                sender_id,
                                command_line,
                                queue_result.get("job_id"),
                                queue_result.get("command_id"),
                            )
                        else:
                            logging.warning(f"No valid recipients or commands found in email from {sender_email}. Ignoring.")
                    
                    processed_uids.append(msg.uid)
                except Exception as e:
                    logging.error(f"Failed to process email UID {msg.uid}. Subject: '{msg.subject}'. Error: {e}", exc_info=True)
            if processed_uids and settings.TRASH_FOLDER_NAME:
                mailbox.move(processed_uids, settings.TRASH_FOLDER_NAME)
            if rate_limit_enabled and rate_limit_dirty:
                try:
                    with file_lock(settings.EMAIL_RATE_LIMIT_FILE + ".lock"):
                        write_json_atomic(settings.EMAIL_RATE_LIMIT_FILE, rate_limit_state)
                except Exception as e:
                    logging.error(f"Failed to persist email rate limit state: {e}", exc_info=True)
    except Exception as e:
        logging.critical(f"An error occurred during the email processing session: {e}", exc_info=True)

def send_pending_outgoing_emails():
    lock_path = settings.OUTGOING_EMAIL_FILE + ".lock"
    sent_ids = []
    invalid_ids = []
    to_delete = []

    try:
        with file_lock(lock_path):
            messages = gb_db.fetch_outgoing_emails()
            if not messages:
                return
            subscribers = gb_db.load_subscribers_dict() or {}
            with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as smtp:
                smtp.starttls()
                smtp.login(settings.EMAIL_USER, settings.EMAIL_PASS)
                for msg_data in messages:
                    recipient = msg_data.get("recipient")
                    subject = msg_data.get("subject")
                    original_body = msg_data.get("body")
                    sender_node_id = msg_data.get("sender_node", "Meshtastic Node")

                    if not all([recipient, subject, original_body]):
                        reason = "missing recipient/subject/body"
                        logging.warning(
                            "Dropping invalid outgoing email row (%s).", reason
                        )
                        try:
                            gb_db.add_outgoing_email_quarantine(msg_data, reason)
                            gb_db.prune_outgoing_email_quarantine(settings.OUTGOING_EMAIL_QUARANTINE_MAX)
                        except Exception as e:
                            logging.error("Failed to quarantine invalid outgoing email: %s", e, exc_info=True)
                        if msg_data.get("id"):
                            invalid_ids.append(msg_data["id"])
                        continue

                    sender_info = subscribers.get(sender_node_id, {})
                    sender_name = sender_info.get("name", sender_node_id)
                    full_body = ""
                    from_name = f"{sender_name} ({sender_node_id}) via GuardianBridge"

                    if msg_data.get("is_sos", False):
                        # For SOS messages, the sender is the system itself.
                        from_name = "GuardianBridge Alert System"

                        instructions_body = ""
                        if os.path.exists(settings.SOS_EMAIL_INSTRUCTIONS_FILE):
                            try:
                                with open(settings.SOS_EMAIL_INSTRUCTIONS_FILE, 'r') as f:
                                    instructions_body = f.read()
                            except Exception as e:
                                logging.error(f"Could not read SOS instructions file: {e}")

                        # Construct the SOS email body: original message + instructions.
                        # No extra headers or footers.
                        if instructions_body:
                            full_body = f"{original_body}\n\n---\n\n{instructions_body}"
                        else:
                            full_body = original_body
                    else:
                        try:
                            tz = pytz.timezone(get_localzone_name())
                            now = datetime.now(tz)
                            timestamp_str = now.strftime("%H:%M %m/%d")
                        except Exception:
                            now = datetime.now(timezone.utc)
                            timestamp_str = now.strftime("%H:%M %m/%d UTC")
                        header = (
                            f"GuardianBridge Notification\n"
                            f"At {timestamp_str}, {sender_name} ({sender_node_id}) sent the following message:\n\n"
                        )
                        footer = (
                            f"\n\nHow to Reply:\n"
                            f"To ensure your response is successfully delivered, please send a new email with the following details:\n"
                            f"    To: {settings.EMAIL_USER}\n"
                            f"    Subject: For {sender_node_id}\n"
                            f"    (Alternatively, you may use the user's name: {sender_name})\n"
                            f"    Body: Type your reply in the message body and send.\n\n"
                            f"Important Notes:\n"
                            f"- Your entire message\u2014including your email address\u2014must be no more than 190 characters.\n"
                            f"- GuardianBridge automated processing is currently in beta. Do not use it for critical or time-sensitive communication."
                        )
                        full_body = f"{header}{original_body}{footer}"

                    email_msg = MIMEText(full_body)
                    email_msg["Subject"] = subject
                    email_msg["From"] = f"{from_name} <{settings.EMAIL_USER}>"
                    email_msg["To"] = recipient
                    smtp.send_message(email_msg)
                    sent_ids.append(msg_data.get("id"))
                    logging.info(f"Sent email from {sender_name} to {recipient}")
    except Exception as e:
        logging.error(f"Failed to send outgoing emails: {e}", exc_info=True)
    finally:
        # Persist progress even on partial SMTP failure to avoid duplicate re-sends.
        to_delete = [msg_id for msg_id in sent_ids if msg_id]
        to_delete.extend([msg_id for msg_id in invalid_ids if msg_id])
        if to_delete:
            try:
                gb_db.delete_outgoing_emails(to_delete)
            except Exception as delete_err:
                logging.error(f"Failed to delete processed outgoing email rows: {delete_err}", exc_info=True)

if __name__ == "__main__":
    lock_path = os.path.join(settings.DATA_DIR, "email_processor.lock")
    if not acquire_instance_lock(lock_path, max_age_seconds=1800):
        logging.warning("Email processor already running. Exiting.")
        sys.exit(0)
    try:
        logging.info("Email processor starting...")
        process_incoming_emails()
        send_pending_outgoing_emails()
        try:
            Path(settings.EMAIL_PROCESSOR_LASTRUN_FILE).touch()
        except Exception as e:
            logging.error(f"Could not create .lastrun file: {e}")
    finally:
        release_instance_lock(lock_path)
    logging.info("Email processor finished.")
