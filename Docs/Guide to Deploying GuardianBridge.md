# GuardianBridge Deployment Guide (Current 1.4)

This document is the current deployment reference for GuardianBridge 1.4.

For full feature and operations documentation, use:
- `/opt/GuardianBridge/README.md`
- `/opt/GuardianBridge/Docs/ARCHITECTURE.md`

## 1. Prerequisites

- Linux host (Debian/Raspberry Pi OS recommended)
- Python 3.9+
- Meshtastic radio connected via USB
- Apache or Nginx with PHP and SQLite support
- `php-sqlite3` package installed

## 2. Install GuardianBridge

```bash
git clone <repo-url> ~/guardian-bridge
sudo mv ~/guardian-bridge /opt/GuardianBridge
sudo mkdir -p /opt/GuardianBridge/data
sudo chown -R <app_user>:<app_group> /opt/GuardianBridge
cd /opt/GuardianBridge
pip3 install -r requirements.txt
```

## 3. Configure Environment

```bash
cp .env.example .env
nano .env
```

Set at minimum:
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD_HASH`
- email/IMAP/SMTP settings
- GPS and broadcast settings

Generate admin hash:
```bash
php -r "echo password_hash('YourPassword', PASSWORD_DEFAULT) . PHP_EOL;"
```

## 4. Deploy Web Files

```bash
sudo cp /opt/GuardianBridge/www/map.php /var/www/html/map.php
sudo cp /opt/GuardianBridge/www/mop.php /var/www/html/mop.php
sudo cp /opt/GuardianBridge/www/db.php /var/www/html/db.php
sudo cp -r /opt/GuardianBridge/www/map-items /var/www/html/map-items
sudo ln -sf /var/www/html/map.php /var/www/html/index.php
```

## 5. Permissions (Critical)

GuardianBridge uses SQLite WAL mode. The DB file and DB directory must be writable by both the dispatcher user and web server group.

Recommended baseline:
```bash
sudo usermod -a -G www-data <app_user>
sudo chown -R <app_user>:www-data /opt/GuardianBridge
sudo find /opt/GuardianBridge -type d -exec chmod 2775 {} \;
sudo find /opt/GuardianBridge -type f -exec chmod 664 {} \;
sudo chmod 640 /opt/GuardianBridge/.env
```

After group changes, log out/in or reboot.

## 6. Create Service

`/etc/systemd/system/guardianbridge.service`:

```ini
[Unit]
Description=GuardianBridge System
After=network.target

[Service]
Type=simple
User=<app_user>
Group=<app_group>
WorkingDirectory=/opt/GuardianBridge
ExecStart=/usr/bin/python3 /opt/GuardianBridge/meshtastic_dispatcher.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable/start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable guardianbridge.service
sudo systemctl start guardianbridge.service
```

## 7. Cron Jobs

```bash
*/15 * * * * /usr/bin/python3 /opt/GuardianBridge/weather_fetcher.py >> /opt/GuardianBridge/data/cron.log 2>&1
*/5 * * * * /usr/bin/python3 /opt/GuardianBridge/email_processor.py >> /opt/GuardianBridge/data/cron.log 2>&1
```

## 8. Validation

```bash
sudo systemctl status guardianbridge.service
journalctl -u guardianbridge.service -f
ls -lh /opt/GuardianBridge/data/guardianbridge.db
```

Web checks:
- MAP: `http://<host>/map.php`
- MOP: `http://<host>/mop.php`

## 9. Notes

- MAP/MOP web actions are queued through SQLite command jobs.
- The legacy `data/commands/` file queue is not used by 1.4 runtime.
- Restart dispatcher after `.env` changes.

