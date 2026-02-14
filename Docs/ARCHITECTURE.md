# GuardianBridge Architecture

## Overview

GuardianBridge is split into a core dispatcher package and supporting scripts. The dispatcher owns Meshtastic I/O, command handling, SOS workflows, and scheduled broadcasts. Supporting scripts (email processor, weather fetcher) are isolated and communicate via files in `data/`.

## Module Map

`dispatcher/core.py`
- Main entrypoint, global state, watchdog, periodic tasks, and status updates.

`dispatcher/commands.py`
- Command parsing and user/admin command handlers.

`dispatcher/sos.py`
- SOS workflow, responder coordination, escalations, and SOS log updates.

`dispatcher/weather.py`
- Weather formatting, forecasts, alert broadcasts, and scheduled messages.

`dispatcher/messaging.py`
- Meshtastic send queue, retries, and message routing.

`dispatcher/email_queue.py`
- Outgoing email task creation for standard and SOS notifications.

`gb_db.py`
- SQLite access layer for high-traffic data.

## Data Flow

1. `meshtastic_dispatcher.py` starts the dispatcher, initializes Meshtastic, and launches periodic tasks.
2. Incoming messages are routed to command handlers or tag channels in `dispatcher/messaging.py`.
3. Commands are parsed and processed in `dispatcher/commands.py`.
4. SOS workflows are handled in `dispatcher/sos.py`.
5. Weather and alert broadcasts are handled in `dispatcher/weather.py`.
6. Status and metrics are written to `data/dispatcher_status.json` for the admin panel.

## Database Layout (v1.4.0)

SQLite is used for high-traffic data in `data/guardianbridge.db`:

- `subscribers` (JSON per row)
- `node_status` (JSON per row)
- `chat_log` (JSON per row)
- `sos_log` (JSON per row, with `active` index)
- `dispatcher_jobs` (JSON per row, ordered by `position`)
- `outgoing_emails` (JSON per row)
- `outgoing_emails_quarantine` (JSON per row, pruned by retention limit)
- `failed_dm_queue` (JSON per row)

Legacy JSON files are auto-migrated on first run and treated as read-only. JSON remains in use for caches like `dispatcher_state.json`, `weather_*.json`, and `nws_alerts.json`.

## Normalization Roadmap (Optional v1.4+)

If query volume grows or tag/permission lookups become bottlenecks, consider normalizing:

- `subscribers` table with explicit columns for name/email/phones/address
- `subscriber_tags` join table
- `subscriber_permissions` table

This enables indexed queries like:

```
SELECT s.name, s.email
FROM subscribers s
JOIN subscriber_tags t ON s.node_id = t.node_id
WHERE t.tag = 'SOSM' AND s.blocked = 0;
```

## Adding New Commands

1. Add handler to `dispatcher/commands.py`
2. Register in `COMMAND_HANDLERS`
3. Update help text
4. Add tests in `tests/test_dispatcher.py`
