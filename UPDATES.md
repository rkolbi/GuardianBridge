## GuardianBridge v1.4

This file tracks current release-line notes only.

### Highlights
- SQLite is now the authoritative runtime datastore for web and dispatcher state.
- MAP/MOP command actions are queued through `command_jobs` in SQLite.
- Dead-letter handling uses SQLite-backed `command_dead_letters`.
- Web auth and queue operations include safer failure handling for transient DB issues.
- Dispatcher and UI polling paths were tuned for responsiveness and lower queue latency.

### Operational Notes
- Primary runtime DB: `/opt/GuardianBridge/data/guardianbridge.db`
- Restart dispatcher after `.env` changes:
  - `sudo systemctl restart guardianbridge.service`
