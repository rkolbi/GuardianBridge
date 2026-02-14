import logging
import time
from datetime import datetime
from typing import Optional

import gb_db
import settings
from . import core
from .email_queue import queue_sos_email_notification
from .messaging import broadcast_to_subscribers, send_meshtastic_message


def update_sos_status(node_id: str, sos_code: Optional[str]) -> None:
    with core.node_statuses_lock:
        node_statuses = gb_db.load_node_statuses_dict() or {}
        if node_id not in node_statuses:
            node_statuses[node_id] = {}

        if sos_code:
            node_statuses[node_id]["sos"] = sos_code
            logging.info(f"Set SOS status for {node_id} to {sos_code}")
        elif "sos" in node_statuses.get(node_id, {}):
            del node_statuses[node_id]["sos"]
            logging.info(f"Cleared SOS status for {node_id}")

        gb_db.upsert_node_status(node_id, node_statuses[node_id])


def handle_sos_alert(sender_id: str, sos_code: str, message_payload: str) -> None:
    logging.info(f"SOS '{sos_code}' from {sender_id} with payload: '{message_payload}'. Initiating alert protocol.")

    if core.iface:
        try:
            logging.info(f"Requesting immediate position update from SOS node {sender_id}...")
            core.iface.sendPosition(destinationId=sender_id, wantResponse=True)
            time.sleep(1)
        except Exception as e:
            logging.error(f"Could not request position from {sender_id}: {e}")

    with core.subscribers_lock:
        sender_info = core.subscribers.get(sender_id, {})
        sender_name = sender_info.get("name", f"Unknown ({sender_id})")

    node_statuses = gb_db.load_node_statuses_dict() or {}
    lat = node_statuses.get(sender_id, {}).get("latitude")
    lon = node_statuses.get(sender_id, {}).get("longitude")

    with core.sos_log_lock:
        gb_db.insert_sos_log(
            {
                "timestamp": datetime.now(core.local_tz).isoformat(),
                "sos_type": sos_code,
                "node_id": sender_id,
                "user_info": sender_info,
                "active": True,
                "message_payload": message_payload,
                "latitude": lat,
                "longitude": lon,
                "acknowledged_by": [],
                "responding_list": [],
                "last_checkin_time": datetime.now(core.local_tz).isoformat(),
                "checkin_attempts": 0,
                "escalated_no_ack": False,
                "escalated_unresponsive": False,
            }
        )

    update_sos_status(sender_id, sos_code)

    mesh_recipients = set()
    email_recipients = set()
    with core.subscribers_lock:
        tagged_responders = {node_id for node_id, data in core.subscribers.items() if sos_code in data.get("tags", [])}
        mesh_recipients.update(tagged_responders)

    if sender_info.get("sos_notify"):
        contacts = [c.strip() for c in sender_info["sos_notify"].split(",") if c.strip()]
        for contact in contacts:
            if "@" in contact:
                email_recipients.add(contact.lower())
            elif contact.startswith("!"):
                mesh_recipients.add(contact)
            else:
                with core.subscribers_lock:
                    found_id = next(
                        (nid for nid, data in core.subscribers.items() if (data.get("name") or "").lower() == contact.lower()),
                        None,
                    )
                    if found_id:
                        mesh_recipients.add(found_id)

    location_info = f"LKP: https://www.google.com/maps?q={lat},{lon}" if lat and lon else "Location not available."
    alert_message_1 = f"{core.PREFIX_SOS} {sos_code} from {sender_name}" + (
        f": {message_payload}" if message_payload else ""
    )
    alert_message_2 = f"{core.PREFIX_SOS} {location_info}"

    info_parts = []
    if sender_info.get("full_name"):
        info_parts.append(sender_info["full_name"])
    if sender_info.get("phone_1"):
        info_parts.append(sender_info["phone_1"])
    if sender_info.get("phone_2"):
        info_parts.append(sender_info["phone_2"])

    address_dict = sender_info.get("address", {})
    if isinstance(address_dict, dict):
        if address_dict.get("street"):
            info_parts.append(address_dict["street"])
        if address_dict.get("city"):
            info_parts.append(address_dict["city"])

        state_zip_parts = [part for part in [address_dict.get("state"), address_dict.get("zip")] if part]
        if state_zip_parts:
            info_parts.append(" ".join(state_zip_parts))

    alert_message_3 = ""
    if info_parts:
        info_string = "\n".join(info_parts)
        full_info_message = f"{core.PREFIX_SOS} INFO:\n{info_string}"

        max_len = 200
        if len(full_info_message.encode("utf-8")) > max_len:
            overhead = len(f"{core.PREFIX_SOS} INFO:\n...".encode("utf-8"))
            info_string_bytes = info_string.encode("utf-8")
            truncated_bytes = info_string_bytes[: max_len - overhead]
            info_string = truncated_bytes.decode("utf-8", "ignore").rsplit("\n", 1)[0]
            full_info_message = f"{core.PREFIX_SOS} INFO:\n{info_string}..."
        alert_message_3 = full_info_message

    logging.info(f"Relaying SOS alert to {len(mesh_recipients)} mesh nodes.")
    for r_id in mesh_recipients:
        send_meshtastic_message(alert_message_1, destinationId=r_id, wantAck=True)
        time.sleep(core.MIN_SEND_INTERVAL_SECONDS)
        send_meshtastic_message(alert_message_2, destinationId=r_id, wantAck=True)
        if alert_message_3:
            time.sleep(core.MIN_SEND_INTERVAL_SECONDS)
            send_meshtastic_message(alert_message_3, destinationId=r_id, wantAck=True)

    timestamp_str = core.get_formatted_timestamp()

    address_dict = sender_info.get("address", {})
    address_str = "N/A"
    if isinstance(address_dict, dict):
        address_parts = [
            address_dict.get("street", ""),
            address_dict.get("city", ""),
            address_dict.get("state", ""),
            address_dict.get("zip", ""),
        ]
        address_str = ", ".join(part for part in address_parts if part) or "N/A"

    user_details = "\n".join(
        [
            f"Full Name: {sender_info.get('full_name', 'N/A')}",
            f"Node ID: {sender_id}",
            f"Name: {sender_info.get('name', 'N/A')}",
            f"Phone 1: {sender_info.get('phone_1', 'N/A')}",
            f"Phone 2: {sender_info.get('phone_2', 'N/A')}",
            f"Address: {address_str}",
        ]
    )

    location_url = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else "Location not available."
    email_subject = f"[GuardianBridge ALERT] {sos_code} from {sender_name}"
    email_body = (
        f"A {sos_code} alert was triggered by {sender_name} at {timestamp_str}.\n\n"
        f"Message: {message_payload or 'No message provided.'}\n\n"
        f"--- User Information ---\n{user_details}\n\n"
        f"--- Last Known Location ---\n{location_url}\n\n"
        "This is an automated alert."
    )
    queue_sos_email_notification(sos_code, email_subject, email_body, extra_recipients=email_recipients)

    send_meshtastic_message(
        f"{core.PREFIX_BOT_RESPONSE} Your {sos_code} has been received. Alerting assigned personnel.",
        destinationId=sender_id,
        wantAck=True,
    )


def handle_sos_clear(sender_id: str, admin_clear: bool = False) -> None:
    logging.info(f"SOS CLEAR initiated for {sender_id}." + (" (Admin)" if admin_clear else ""))

    with core.sos_log_lock:
        active_sos_entry = next((e for e in gb_db.load_active_sos_logs() if e.get("node_id") == sender_id), None)
        if not active_sos_entry:
            logging.warning(f"Received CLEAR for {sender_id}, but no active SOS was found.")
            if not admin_clear:
                send_meshtastic_message(
                    f"{core.PREFIX_BOT_RESPONSE} You have no active alert to clear.", destinationId=sender_id, wantAck=True
                )
            return

        active_sos_code = active_sos_entry["sos_type"]
        active_sos_entry["active"] = False
        gb_db.update_sos_log(active_sos_entry["id"], active_sos_entry)

    update_sos_status(sender_id, None)

    with core.subscribers_lock:
        clearer_name = core.subscribers.get(sender_id, {}).get("name", sender_id)
        responders = {node_id for node_id, data in core.subscribers.items() if active_sos_code in data.get("tags", [])}
        responders.update(active_sos_entry.get("responding_list", []))
        responders.update(active_sos_entry.get("acknowledged_by", []))

    if responders:
        stand_down_message = f"STAND DOWN: {clearer_name} has cleared the {active_sos_code} alert."
        logging.info(f"Sending stand down message to {len(responders)} responders.")
        for responder_id in responders:
            send_meshtastic_message(stand_down_message, destinationId=responder_id, wantAck=True)

    timestamp_str = core.get_formatted_timestamp()
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
    queue_sos_email_notification(active_sos_code, email_subject, email_body)

    if not admin_clear:
        send_meshtastic_message(
            f"{core.PREFIX_BOT_RESPONSE} Your {active_sos_code} alert has been cleared.",
            destinationId=sender_id,
            wantAck=True,
        )


def handle_sos_action_initial(sender_id: str, command: str) -> None:
    with core.sos_log_lock:
        active_sos_events = gb_db.load_active_sos_logs() or []

    if not active_sos_events:
        send_meshtastic_message(
            f"{core.PREFIX_BOT_RESPONSE} There are no active SOS alerts.", destinationId=sender_id, wantAck=True
        )
        return

    if len(active_sos_events) == 1:
        target_sos_id = active_sos_events[0]["node_id"]
        if command in core.ACK_COMMANDS:
            handle_sos_ack(sender_id, target_sos_id)
        elif command in core.RESPONDING_COMMANDS:
            handle_sos_responding(sender_id, target_sos_id)
    else:
        with core.user_interaction_state_lock:
            core.user_interaction_state[sender_id] = "awaiting_sos_choice"
            with core.subscribers_lock:
                menu_text = "Multiple active alerts. Reply with command and number (e.g., ACK 2):\n"
                for i, sos in enumerate(active_sos_events, 1):
                    sender_name = core.subscribers.get(sos["node_id"], {}).get("name", sos["node_id"])
                    menu_text += f"{i}. {sos['sos_type']} from {sender_name}\n"
            send_meshtastic_message(menu_text, destinationId=sender_id, wantAck=True)


def handle_sos_choice(responder_id: str, command: str, choice_num: int) -> None:
    with core.sos_log_lock:
        active_sos_events = gb_db.load_active_sos_logs() or []

    if 0 < choice_num <= len(active_sos_events):
        target_sos_id = active_sos_events[choice_num - 1]["node_id"]
        if command.upper() in core.ACK_COMMANDS:
            handle_sos_ack(responder_id, target_sos_id)
        elif command.upper() in core.RESPONDING_COMMANDS:
            handle_sos_responding(responder_id, target_sos_id)
    else:
        send_meshtastic_message(
            f"{core.PREFIX_BOT_RESPONSE} Invalid selection. Please try again.",
            destinationId=responder_id,
            wantAck=True,
        )


def handle_sos_ack(responder_id: str, target_sos_id: str) -> None:
    with core.sos_log_lock:
        active_sos = next((e for e in gb_db.load_active_sos_logs() if e.get("node_id") == target_sos_id), None)
        if not active_sos:
            return

        if responder_id not in active_sos.get("acknowledged_by", []):
            active_sos.setdefault("acknowledged_by", []).append(responder_id)
            gb_db.update_sos_log(active_sos["id"], active_sos)
            logging.info(f"SOS from {target_sos_id} acknowledged by {responder_id}.")
            send_meshtastic_message(
                f"{core.PREFIX_BOT_RESPONSE} Your ACK has been logged.", destinationId=responder_id, wantAck=True
            )
        else:
            send_meshtastic_message(
                f"{core.PREFIX_BOT_RESPONSE} You have already acknowledged this alert.",
                destinationId=responder_id,
                wantAck=True,
            )


def handle_sos_responding(responder_id: str, target_sos_id: str) -> None:
    with core.sos_log_lock:
        active_sos = next((e for e in gb_db.load_active_sos_logs() if e.get("node_id") == target_sos_id), None)
        if not active_sos:
            logging.warning(f"Received RESPONDING from {responder_id} for inactive/invalid SOS {target_sos_id}.")
            return

        active_sos.setdefault("responding_list", [])
        if responder_id in active_sos["responding_list"]:
            logging.info(f"User {responder_id} is already marked as responding. Ignoring duplicate command.")
            send_meshtastic_message(
                f"{core.PREFIX_BOT_RESPONSE} You are already marked as responding to this alert.",
                destinationId=responder_id,
                wantAck=True,
            )
            return

        active_sos["responding_list"].append(responder_id)
        if "acknowledged_by" in active_sos and responder_id in active_sos["acknowledged_by"]:
            active_sos["acknowledged_by"].remove(responder_id)
        gb_db.update_sos_log(active_sos["id"], active_sos)

    with core.subscribers_lock:
        responder_name = core.subscribers.get(responder_id, {}).get("name", responder_id)
        sos_user_name = active_sos.get("user_info", {}).get("name", active_sos["node_id"])

    update_msg = f"[SOS UPDATE] {responder_name} is now also responding to the {active_sos['sos_type']} from {sos_user_name}."
    logging.info(update_msg)

    with core.subscribers_lock:
        all_participants = set(active_sos.get("acknowledged_by", []) + active_sos.get("responding_list", []))
        tagged_responders = {node_id for node_id, data in core.subscribers.items() if active_sos["sos_type"] in data.get("tags", [])}
        responders_to_notify = (all_participants.union(tagged_responders)) - {responder_id}

    for r_id in responders_to_notify:
        send_meshtastic_message(update_msg, destinationId=r_id, wantAck=True)

    sos_author_id = active_sos.get("node_id")
    if sos_author_id:
        with core.subscribers_lock:
            responding_names = [core.subscribers.get(r_id, {}).get("name", r_id) for r_id in active_sos["responding_list"]]
        names_str = ", ".join(responding_names)
        confirmation_for_author = f"{core.PREFIX_BOT_RESPONSE} Help is on the way. Responding: {names_str}."
        send_meshtastic_message(confirmation_for_author, destinationId=sos_author_id, wantAck=True)

    send_meshtastic_message(
        f"{core.PREFIX_BOT_RESPONSE} You are now marked as responding.", destinationId=responder_id, wantAck=True
    )


def handle_sos_checkin_response(sender_id: str) -> None:
    with core.sos_log_lock:
        active_sos = next((e for e in gb_db.load_active_sos_logs() if e.get("node_id") == sender_id), None)
        if not active_sos:
            return

        active_sos["last_checkin_time"] = datetime.now(core.local_tz).isoformat()
        active_sos["checkin_attempts"] = 0
        gb_db.update_sos_log(active_sos["id"], active_sos)
        logging.info(f"Received check-in response from {sender_id}. Resetting attempt counter.")


def handle_active_sos_tasks(now: datetime) -> None:
    with core.sos_log_lock:
        active_sos_events = gb_db.load_active_sos_logs() or []
        if not active_sos_events:
            return

        for active_sos in active_sos_events:
            entry_modified = False
            if (
                not active_sos.get("acknowledged_by")
                and not active_sos.get("responding_list")
                and not active_sos.get("escalated_no_ack", False)
            ):
                sos_start_time = datetime.fromisoformat(active_sos["timestamp"])
                if (now - sos_start_time).total_seconds() > settings.SOS_ACK_TIMEOUT_MINS * 60:
                    logging.warning(
                        f"SOS from {active_sos['node_id']} has not been acknowledged after {settings.SOS_ACK_TIMEOUT_MINS} mins. Escalating network-wide."
                    )

                    sender_name = active_sos.get("user_info", {}).get("name", active_sos["node_id"])
                    payload = active_sos.get("message_payload", "")

                    location_info = "Location not available."
                    lat, lon = active_sos.get("latitude"), active_sos.get("longitude")
                    if lat and lon:
                        location_info = f"LKP: https://www.google.com/maps?q={lat},{lon}"

                    alert_msg_1 = f"{core.PREFIX_SOS} {active_sos['sos_type']} from {sender_name}" + (
                        f": {payload}" if payload else ""
                    )
                    alert_msg_2 = f"{core.PREFIX_SOS} {location_info}"

                    broadcast_to_subscribers(f"[WIDE ALERT] {alert_msg_1}", "alerts")
                    time.sleep(core.MIN_SEND_INTERVAL_SECONDS)
                    broadcast_to_subscribers(f"[WIDE ALERT] {alert_msg_2}", "alerts")

                    active_sos["escalated_no_ack"] = True
                    entry_modified = True

            last_checkin_raw = active_sos.get("last_checkin_time")
            if last_checkin_raw:
                last_checkin_time = datetime.fromisoformat(last_checkin_raw)
                if (now - last_checkin_time).total_seconds() > settings.SOS_CHECKIN_INTERVAL_MINS * 60:
                    attempts = active_sos.get("checkin_attempts", 0)
                    if attempts >= settings.SOS_CHECKIN_MAX_ATTEMPTS:
                        if not active_sos.get("escalated_unresponsive", False):
                            logging.warning(f"SOS user {active_sos['node_id']} is UNRESPONSIVE. Escalating alert.")
                            sender_name = active_sos.get("user_info", {}).get("name", active_sos["node_id"])

                            with core.subscribers_lock:
                                all_participants = set(
                                    active_sos.get("acknowledged_by", []) + active_sos.get("responding_list", [])
                                )
                                tagged_responders = {
                                    node_id
                                    for node_id, data in core.subscribers.items()
                                    if active_sos["sos_type"] in data.get("tags", [])
                                }
                                responders_to_notify = all_participants.union(tagged_responders)

                            escalation_msg = (
                                f"[SOS ESCALATION] User {sender_name} is UNRESPONSIVE. Last check-in failed."
                            )
                            for r_id in responders_to_notify:
                                send_meshtastic_message(escalation_msg, destinationId=r_id, wantAck=True)

                            active_sos["escalated_unresponsive"] = True
                            entry_modified = True
                    else:
                        logging.info(f"Sending check-in ping to {active_sos['node_id']} (Attempt {attempts + 1})")
                        send_meshtastic_message(
                            "[CHECK-IN] Are you OK? Please reply Y if you are.",
                            destinationId=active_sos["node_id"],
                            wantAck=True,
                        )
                        active_sos["last_checkin_time"] = now.isoformat()
                        active_sos["checkin_attempts"] = attempts + 1
                        entry_modified = True

            if entry_modified:
                gb_db.update_sos_log(active_sos["id"], active_sos)
