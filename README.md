# GuardianBridge: A Resilient Meshtastic Gateway

GuardianBridge is a complete, self-contained communication gateway system. It leverages the power of LoRa (Long Range) mesh networking through the Meshtastic platform to create an independent, resilient communication network that your community builds and owns.

It acts as a lifeline when traditional infrastructure fails, providing critical information and a means of contact to keep your community safe, informed, and connected when it matters most.

## Why GuardianBridge?

In times of severe weather, natural disasters, or infrastructure failure, cellular networks and internet are often the first systems to go down. GuardianBridge is built to solve this problem by bridging a resilient, off-grid Meshtastic network to essential internet services, ensuring your community's communication lines stay open.

- **System Philosophy**: Resilience over Speed, Modularity, and Efficiency for low-power devices like the Raspberry Pi.
- **Satellite Resilient**: When connected to a satellite internet provider, the gateway remains resilient to local terrestrial infrastructure damage.

## Core Capabilities

GuardianBridge provides a rich set of automated and on-demand features:

- **Automated Weather & Forecasts**: Receive periodic updates on current weather conditions and scheduled daily forecasts.
- **Critical NWS Alerts**: Get timely, automated alerts from the National Weather Service for severe events.
- **Two-Way Email Gateway**: Send and receive emails from the mesh network using simple commands.
- **Email-Based Broadcasts**: Authorized administrators can send network-wide broadcast messages via email.
- **Tag-Based Group Messaging**: Create logical groups (e.g., `CERT`, `MEDICAL`) for targeted messages.
- **Flexible Scheduled Broadcasts**: Configure custom, recurring, or one-time event announcements via the Admin Panel.
- **User Self-Service**: Users can manage their subscriptions and settings via direct messages to the gateway.
- **SOS Emergency Alert System**: Users can trigger an alert (general, police, fire, medical) and admins can manage the response, including remote clearance.
- **Offline Map Support**: The system includes a utility to pre-download map tiles, ensuring the Admin Panel map is functional even if the gateway loses its internet connection.

## Critical Network Configuration for Stability

For a reliable alert system, **your #1 enemy is network congestion, not range**. A well-configured network can support thousands of nodes, while a poorly configured one can fail under heavy load. The following settings are critical for a stable and high-performance network.

### 1. LoRa Modem Preset

All nodes in your network **must** use the same modem preset. The recommended setting for GuardianBridge is **`MEDIUM_FAST`**. This preset offers 3-4 times the network capacity of the default (`LONG_FAST`), drastically reducing the risk of congestion while maintaining excellent range.

```
meshtastic --set lora.modem_preset MEDIUM_FAST
```

### 2. Node Roles

A stable mesh requires specific roles. Misconfiguration is a leading cause of network failure.

- **`ROUTER`**: Only for high-elevation, permanently powered backbone nodes.
- **`CLIENT`**: For most fixed-location nodes (homes, offices, the GuardianBridge gateway node).
- **`CLIENT_MUTE`**: **Mandatory for any mobile node** (handhelds, vehicles). This prevents moving nodes from destabilizing the network's message routing by not rebroadcasting packets.

### 3. Network Isolation and Security

- **Private Channel**: Always create a new primary channel with a random Pre-Shared Key (PSK) and delete the default public channel to prevent interference.

  ```
  meshtastic --ch-add "private-channel-name" --ch-set psk random
  meshtastic --ch-del DEFAULT
  ```

- **Advanced Security**: For critical infrastructure nodes, use "Remote Administration" to manage them securely over the mesh and enable "Managed Mode" to prevent local tampering.

## Installation & Setup

**Note:** These instructions are for Debian-based systems like Raspberry Pi OS (default user `pi`) and DietPi (default user `dietpi`). Please adjust the username and group in the commands below to match your system.

### Prerequisites

- A Linux server (Raspberry Pi OS or DietPi recommended) with Python 3.9+ and Git.
- A Meshtastic device connected to the server via USB.
- A web server with PHP support (e.g., Apache2, Lighttpd) and the `shell_exec` function enabled.
- An email account for the gateway (a Gmail account with a 16-digit App Password is recommended).

### Step 1: Install Backend Services

```
# Clone the repository and move it to the recommended directory
git clone <your-repository-url> ~/guardian-bridge
sudo mv ~/guardian-bridge /opt/GuardianBridge

# Create data directories and set ownership
sudo mkdir -p /opt/GuardianBridge/data/commands
# For Raspberry Pi OS:
sudo chown -R pi:pi /opt/GuardianBridge 
# For DietPi:
sudo chown -R dietpi:dietpi /opt/GuardianBridge
cd /opt/GuardianBridge

# Install Python dependencies
pip3 install -r requirements.txt
```

### Step 2: Install Web Admin Panel

```
# For Raspberry Pi OS (or other Debian-based systems):
sudo apt-get update && sudo apt-get install apache2 php libapache2-mod-php -y

# For DietPi (Recommended): Use the optimized software installer
sudo dietpi-software install 113 # Installs Lighttpd webserver
sudo dietpi-software install 114 # Installs PHP

# Copy the admin panel file
sudo cp /path/to/your/map.php /var/www/html/index.php

# Set crucial file permissions (CRITICAL STEP)
# For Raspberry Pi OS:
sudo usermod -a -G www-data pi
sudo chown -R pi:www-data /opt/GuardianBridge
# For DietPi:
sudo usermod -a -G www-data dietpi
sudo chown -R dietpi:www-data /opt/GuardianBridge

# Set shared permissions for the directory
sudo chmod -R 775 /opt/GuardianBridge
# A system reboot is required for the group change to take effect.
```

### Step 3: Configure the System

1. **Create and edit the `.env` file** (`cp .env.txt .env` and then `nano .env`) with your specific details.
2. **Set a secure Admin Password** by generating a password hash and placing it in the `$admin_password_hash` variable in `map.php`.

### Step 4: Enable and Start Services

1. **Create the dispatcher service file** at `sudo nano /etc/systemd/system/guardianbridge.service`:

   **Important**: Change `User` and `Group` from `pi` to `dietpi` if you are using DietPi.

   ```
   [Unit]
   Description=Meshtastic Dispatcher Service
   After=network.target
   
   [Service]
   Type=simple
   User=dietpi
   Group=dietpi
   WorkingDirectory=/opt/GuardianBridge
   ExecStart=/usr/bin/python3 /opt/GuardianBridge/meshtastic_dispatcher.py
   Restart=on-failure
   RestartSec=10
   
   [Install]
   WantedBy=multi-user.target
   ```

2. **Enable and start the service:**

   ```
   sudo systemctl daemon-reload
   sudo systemctl enable guardianbridge.service
   sudo systemctl start guardianbridge.service
   ```

3. **Set up Cron Jobs** (`crontab -e`):

   ```
   */15 * * * * /usr/bin/python3 /opt/GuardianBridge/weather_fetcher.py >> /opt/GuardianBridge/data/cron.log 2>&1
   */5 * * * * /usr/bin/python3 /opt/GuardianBridge/email_processor.py >> /opt/GuardianBridge/data/cron.log 2>&1
   ```

## Contributing

Contributions are welcome! If you have an idea for a new feature or have found a bug, please open an issue on the GitHub repository. If you'd like to contribute code, please fork the repository and submit a pull request.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
