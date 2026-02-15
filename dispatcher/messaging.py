import logging
import time
from datetime import datetime
from typing import Any, Dict

import meshtastic

import gb_db
from . import core


def send_meshtastic_message(text: str, **kwargs: Any) -> None:
    priority = bool(kwargs.pop("priority", False))
    warn_queue_wait = bool(kwargs.pop("warn_queue_wait", True))
    kwargs["text"] = text
    kwargs["_queued_at"] = time.time()
    kwargs["_warn_queue_wait"] = warn_queue_wait
    if priority:
        core.send_priority_queue.put(kwargs)
    else:
        core.send_queue.put(kwargs)


def sender_thread_worker() -> None:
    logging.info("Sender thread started.")
    while True:
        try:
            kwargs = core.dequeue_send_job()
            if kwargs is None:
                if core.send_priority_queue.empty() and core.send_queue.empty():
                    break
                continue

            queued_at = kwargs.pop("_queued_at", None)
            warn_queue_wait = bool(kwargs.pop("_warn_queue_wait", True))
            if isinstance(queued_at, (int, float)):
                queue_wait_ms = max(0.0, (time.time() - float(queued_at)) * 1000.0)
                if warn_queue_wait:
                    core.record_latency_sample("send_queue_wait_ms", queue_wait_ms)
                    if queue_wait_ms >= core.SEND_QUEUE_WAIT_WARN_MS:
                        destination_preview = kwargs.get("destinationId")
                        logging.warning(
                            f"Send queue wait high ({queue_wait_ms:.1f}ms) for destination {destination_preview or 'Broadcast'}."
                        )

            start_monotonic = time.perf_counter()

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

            elapsed_send = time.perf_counter() - start_monotonic
            send_exec_ms = max(0.0, elapsed_send * 1000.0)
            core.record_latency_sample("send_exec_ms", send_exec_ms)
            if send_exec_ms >= core.SEND_EXEC_WARN_MS:
                logging.warning(
                    f"Send execution slow ({send_exec_ms:.1f}ms) for destination {destination_id or 'Broadcast'}."
                )
            if elapsed_send < core.MIN_SEND_INTERVAL_SECONDS:
                time.sleep(core.MIN_SEND_INTERVAL_SECONDS - elapsed_send)

        except Exception as e:
            logging.error(f"Error in sender thread: {e}", exc_info=True)
            core.record_runtime_error("sender_thread_worker", str(e))


def broadcast_to_subscribers(
    message: str,
    subscription_key: str,
    *,
    priority: bool = False,
    warn_queue_wait: bool = True,
) -> None:
    with core.subscribers_lock:
        current_subscribers = list(core.subscribers.items())
    for sender_id, sub_data in current_subscribers:
        if sub_data.get(subscription_key, False) and not sub_data.get("blocked", False):
            send_meshtastic_message(
                message,
                destinationId=sender_id,
                wantAck=True,
                priority=priority,
                warn_queue_wait=warn_queue_wait,
            )


def retry_queued_messages_for_node(node_id: str) -> None:
    with core.dm_queue_lock:
        messages_for_node = gb_db.fetch_failed_dm_for_node(node_id)
        if not messages_for_node:
            return
        logging.info(f"Node {node_id} is online. Retrying {len(messages_for_node)} queued message(s).")
        gb_db.delete_failed_dm([msg["id"] for msg in messages_for_node if "id" in msg])
    for msg in messages_for_node:
        send_meshtastic_message(text=msg["text"], destinationId=msg["destination_id"], wantAck=True)


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

    sender_status = gb_db.get_node_status(sender) or {}
    active_tag_channel = sender_status.get("active_tag_channel")

    from .commands import COMMAND_HANDLERS, parse_command_text

    command_word, _ = parse_command_text(text)

    if command_word in ["tagin", "tagout"]:
        core.enqueue_command(sender, text)
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
            core.enqueue_command(sender, tagsend_command_text)
            return

    core.enqueue_command(sender, text)
