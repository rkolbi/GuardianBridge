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
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import settings
from pathlib import Path
from tzlocal import get_localzone_name
from imap_tools import MailBox, AND
from bs4 import BeautifulSoup
import pytz
from dateutil.tz import gettz

from contextlib import contextmanager
# Logging setup
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, "INFO"), format="%(asctime)s [%(levelname)s] %(message)s")

VALID_COMMANDS = {"subscribe", "unsubscribe", "alerts on", "alerts off", "weather on", "weather off", "forecasts on", "forecasts off", "status", "help", "?", "name"}

def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)

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

def load_json(path):
    if not os.path.exists(path): return None
    try:
        with open(path, "r") as f: return json.load(f)
    except Exception as e:
        logging.error(f"Error loading JSON from {path}: {e}")
        return None

def clean_forwarded_body(body):
    """Cleans forwarded/replied-to text from an email body using a master separator pattern."""
    original_len = len(body)
    master_separator_pattern = re.compile(
        r"sent the following message:|-----Original Message-----|^\s*>?\s*On .* wrote:\s*$",
        re.IGNORECASE | re.MULTILINE
    )
    parts = master_separator_pattern.split(body, maxsplit=1)
    cleaned_body = parts[0].strip()
    if len(cleaned_body) < original_len:
        logging.info(f"Cleaned forwarded content from email body. Original length: {original_len}, New length: {len(cleaned_body)}")
    return cleaned_body

def find_and_authorize_broadcast_sender(sender_email, subscribers):
    """
    Checks if the sender is authorized to send broadcasts.
    Returns the sender's name if authorized, otherwise None.
    """
    for node_id, data in subscribers.items():
        if data.get('email', '').lower() == sender_email.lower():
            if data.get('emailbroadcast', False):
                return data.get('name', 'Unknown User')
    return None

def send_feedback_email(recipient, subject, body):
    """Sends a feedback email (e.g., success or rejection notice)."""
    try:
        with smtplib.SMTP(settings.IMAP_SERVER, 587) as smtp:
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
    os.makedirs(settings.COMMANDS_DIR, exist_ok=True)
    subscribers = load_json(settings.SUBSCRIBERS_FILE) or {}
    processed_uids = []
    try:
        with MailBox(settings.IMAP_SERVER, port=settings.IMAP_PORT).login(settings.EMAIL_USER, settings.EMAIL_PASS, initial_folder="INBOX") as mailbox:
            for msg in mailbox.fetch(AND(seen=False)):
                try:
                    logging.info(f"Processing email from {msg.from_}: {msg.subject}")
                    sender_email = msg.from_
                    subject_raw = msg.subject.strip()
                    subject_lower = subject_raw.lower()
                    raw_body = msg.text or BeautifulSoup(msg.html, 'html.parser').get_text(separator='\n').strip()
                    
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
                            if max_body_len < 0: max_body_len = 0

                            truncated_body = cleaned_body.encode('utf-8')[:max_body_len].decode('utf-8', errors='ignore')
                            
                            message_to_send = prefix + truncated_body
                            if is_alert:
                                message_to_send = "\x07" + message_to_send

                            command_data = {"command": "broadcast", "text": message_to_send, "timestamp": datetime.utcnow().isoformat()}
                            cmd_filename = f"broadcast_{sanitize_filename(sender_email)}_{int(datetime.utcnow().timestamp())}.json"
                            cmd_path = os.path.join(settings.COMMANDS_DIR, cmd_filename)
                            with open(cmd_path, "w") as f: json.dump(command_data, f)
                            logging.info(f"Saved broadcast command to {cmd_path}")
                            
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
                                user_tags = sub_data.get('tags', [])
                                if any(tag in user_tags for tag in target_tags) and sub_data.get('email_receive', False):
                                    recipient_ids.add(node_id)

                            if recipient_ids:
                                final_recipients = list(recipient_ids)
                                cleaned_body = clean_forwarded_body(raw_body)
                                
                                header_part = f"{sender_email}\n"
                                max_body_len = 190 - len(header_part) 
                                truncated_body = cleaned_body[:max_body_len]
                                message_to_send = header_part + truncated_body

                                command_data = {"command": "relay", "recipients": final_recipients, "text": message_to_send, "timestamp": datetime.utcnow().isoformat()}
                                cmd_filename = f"tag_relay_{sanitize_filename(sender_email)}_{int(datetime.utcnow().timestamp())}.json"
                                cmd_path = os.path.join(settings.COMMANDS_DIR, cmd_filename)
                                with open(cmd_path, "w") as f: json.dump(command_data, f)
                                logging.info(f"Saved tag-based relay command to {cmd_path} for {len(final_recipients)} recipients.")

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

                        if max_body_len_bytes < 0: max_body_len_bytes = 0

                        encoded_body = cleaned_body.encode('utf-8')
                        truncated_body = encoded_body[:max_body_len_bytes].decode('utf-8', errors='ignore')

                        message_to_send = header_part + truncated_body
                        logging.info(f"Constructed message for relay. Length: {len(message_to_send.encode('utf-8'))} bytes.")
                        
                        command_data = {"command": "relay", "recipients": final_recipients, "text": message_to_send, "timestamp": datetime.utcnow().isoformat()}
                        cmd_filename = f"relay_{sanitize_filename(sender_email)}_{int(datetime.utcnow().timestamp())}.json"
                        cmd_path = os.path.join(settings.COMMANDS_DIR, cmd_filename)
                        with open(cmd_path, "w") as f: json.dump(command_data, f)
                        logging.info(f"Saved relay command to {cmd_path} for recipients {final_recipients}")
                    else:
                        sender_id = f"email_{sanitize_filename(sender_email)}"
                        command_line = raw_body.strip().splitlines()[0].lower().strip()
                        if command_line in VALID_COMMANDS:
                            cmd_path = os.path.join(settings.COMMANDS_DIR, f"{sender_id}_cmd.json")
                            command_data = { "sender": sender_id, "command": command_line, "timestamp": datetime.utcnow().isoformat() }
                            with open(cmd_path, "w") as f: json.dump(command_data, f)
                            logging.info(f"Saved standard command for {sender_id}: '{command_line}'")
                        else:
                            logging.warning(f"No valid recipients or commands found in email from {sender_email}. Ignoring.")
                    
                    processed_uids.append(msg.uid)
                except Exception as e:
                    logging.error(f"Failed to process email UID {msg.uid}. Subject: '{subject_raw}'. Error: {e}", exc_info=True)
            if processed_uids and settings.TRASH_FOLDER_NAME:
                mailbox.move(processed_uids, settings.TRASH_FOLDER_NAME)
    except Exception as e:
        logging.critical(f"An error occurred during the email processing session: {e}", exc_info=True)

def send_pending_outgoing_emails():
    if not os.path.exists(settings.OUTGOING_EMAIL_FILE): return
    lock_path = settings.OUTGOING_EMAIL_FILE + ".lock"

    try:
        with file_lock(lock_path):
            messages = load_json(settings.OUTGOING_EMAIL_FILE) or []
            if not messages: return
            subscribers = load_json(settings.SUBSCRIBERS_FILE) or {}
            with smtplib.SMTP(settings.IMAP_SERVER, 587) as smtp:
                smtp.starttls()
                smtp.login(settings.EMAIL_USER, settings.EMAIL_PASS)
                for msg_data in messages:
                    recipient = msg_data.get("recipient")
                    subject = msg_data.get("subject")
                    original_body = msg_data.get("body")
                    sender_node_id = msg_data.get("sender_node", "Meshtastic Node")

                    if not all([recipient, subject, original_body]): continue
                    
                    sender_info = subscribers.get(sender_node_id, {})
                    sender_name = sender_info.get("name", sender_node_id)
                    full_body = ""

                    # If the message is an SOS alert, append the custom instructions.
                    if msg_data.get("is_sos", False):
                        instructions_body = ""
                        if os.path.exists(settings.SOS_EMAIL_INSTRUCTIONS_FILE):
                            try:
                                with open(settings.SOS_EMAIL_INSTRUCTIONS_FILE, 'r') as f:
                                    instructions_body = f.read()
                            except Exception as e:
                                logging.error(f"Could not read SOS instructions file: {e}")
                        
                        full_body = f"{original_body}\n\n{instructions_body}"
                    else:
                        try:
                            tz = pytz.timezone(get_localzone_name())
                            now = datetime.now(tz)
                            timestamp_str = now.strftime("%H:%M %m/%d")
                        except Exception:
                            now = datetime.utcnow()
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
                            f"- Your entire message—including your email address—must be no more than 190 characters.\n"
                            f"- GuardianBridge automated processing is currently in beta. Do not use it for critical or time-sensitive communication."
                        )
                        full_body = f"{header}{original_body}{footer}"

                    email_msg = MIMEText(full_body)
                    email_msg["Subject"] = subject
                    email_msg["From"] = f"{sender_name} ({sender_node_id}) via GuardianBridge <{settings.EMAIL_USER}>"
                    email_msg["To"] = recipient
                    smtp.send_message(email_msg)
                    logging.info(f"Sent email from {sender_name} to {recipient}")
            with open(settings.OUTGOING_EMAIL_FILE, "w") as f: json.dump([], f)
    except Exception as e:
        logging.error(f"Failed to send outgoing emails: {e}", exc_info=True)

if __name__ == "__main__":
    logging.info("Email processor starting...")
    process_incoming_emails()
    send_pending_outgoing_emails()
    try:
        Path(settings.EMAIL_PROCESSOR_LASTRUN_FILE).touch()
    except Exception as e:
        logging.error(f"Could not create .lastrun file: {e}")
    logging.info("Email processor finished.")
