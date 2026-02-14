import logging
import time
from datetime import datetime
from typing import Any, Dict

import meshtastic

import gb_db
from . import core


def send_meshtastic_message(text: str, **kwargs: Any) -> None:
    kwargs["text"] = text
    core.send_queue.put(kwargs)


def sender_thread_worker() -> None:
    logging.info("Sender thread started.")
    while True:
        try:
            kwargs = core.send_queue.get()
            if kwargs is None:
                break

            start_time = time.time()

            text = kwargs.get("text")
            destination_id = kwargs.get("destinationId")
            text_for_log = kwargs.pop("text_for_log", text)
            suppress_log = kwargs.pop("suppress_log", False)

            if not suppress_log:
                core.log_channel_message("GATEWAY", text_for_log, is_dm=(destination_id is not None))

            if core.iface:
                try:
                    core.iface.sendText(**kwargs)
                    logging.info(f"Sent: '{text}' -> {destination_id or 'Broadcast'}")
                except meshtastic.MeshtasticException as e:
                    logging.warning(f"Failed to send message to {destination_id}: {e}. Queuing for retry.")
                    if destination_id:
                        with core.dm_queue_lock:
                            gb_db.add_failed_dm(
                                {
                                    "destination_id": destination_id,
                                    "text": text,
                                    "timestamp": datetime.now(core.local_tz).isoformat(),
                                }
                            )
                except Exception as e:
                    logging.error(f"Unexpected error sending message to {destination_id}: {e}", exc_info=True)

            elapsed = time.time() - start_time
            if elapsed < core.MIN_SEND_INTERVAL_SECONDS:
                time.sleep(core.MIN_SEND_INTERVAL_SECONDS - elapsed)

        except Exception as e:
            logging.error(f"Error in sender thread: {e}", exc_info=True)
            core.record_runtime_error("sender_thread_worker", str(e))


def broadcast_to_subscribers(message: str, subscription_key: str) -> None:
    with core.subscribers_lock:
        current_subscribers = list(core.subscribers.items())
    for sender_id, sub_data in current_subscribers:
        if sub_data.get(subscription_key, False) and not sub_data.get("blocked", False):
            send_meshtastic_message(message, destinationId=sender_id, wantAck=True)


def retry_queued_messages_for_node(node_id: str) -> None:
    with core.dm_queue_lock:
        messages_for_node = gb_db.fetch_failed_dm_for_node(node_id)
        if not messages_for_node:
            return
        logging.info(f"Node {node_id} is online. Retrying {len(messages_for_node)} queued message(s).")
        gb_db.delete_failed_dm([msg["id"] for msg in messages_for_node if "id" in msg])
    for msg in messages_for_node:
        send_meshtastic_message(text=msg["text"], destinationId=msg["destination_id"], wantAck=True)
        time.sleep(core.MIN_SEND_INTERVAL_SECONDS)


def on_meshtastic_message(packet: Dict[str, Any], interface: Any) -> None:
    decoded = packet.get("decoded", {})
    if decoded.get("portnum") != "TEXT_MESSAGE_APP":
        return

    text = decoded.get("text", "").strip()
    sender = packet.get("fromId")
    destination_id = packet.get("toId")

    if not text or not sender:
        return

    if sender:
        with core.node_last_heard_cache_lock:
            core.node_last_heard_cache[sender] = time.time()
        retry_queued_messages_for_node(sender)

    is_dm_to_gateway = destination_id == core.gateway_node_id
    core.log_channel_message(sender, text, is_dm=is_dm_to_gateway)

    if not is_dm_to_gateway:
        return

    with core.subscribers_lock:
        if core.subscribers.get(sender, {}).get("blocked", False):
            logging.info(f"Ignoring command from blocked user: {sender}")
            return

    if text.startswith(core.BOT_MESSAGE_PREFIXES):
        return

    node_statuses = gb_db.load_node_statuses_dict() or {}
    active_tag_channel = node_statuses.get(sender, {}).get("active_tag_channel")

    from .commands import COMMAND_HANDLERS, parse_command_text

    command_word, _ = parse_command_text(text)

    if command_word in ["tagin", "tagout"]:
        core.command_queue.put((sender, text))
        return

    if active_tag_channel:
        if (
            command_word not in COMMAND_HANDLERS
            and command_word.upper() not in core.SOS_COMMANDS
            and command_word.upper() not in core.CLEAR_COMMANDS
            and command_word.upper() not in core.ACK_COMMANDS.union(core.RESPONDING_COMMANDS)
        ):
            logging.info(f"User {sender} is in tag channel '{active_tag_channel}'. Rerouting message.")
            tagsend_command_text = f"tagsend/{active_tag_channel}/{text}"
            core.command_queue.put((sender, tagsend_command_text))
            return

    core.command_queue.put((sender, text))
