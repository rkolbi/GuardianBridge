# GuardianBridge - System Documentation

## Why GuardianBridge is Essential for Your Community

In times of severe weather, natural disasters, or infrastructure failure, our most basic systems—cellular networks, internet, and power—are often the first to disappear. This leaves communities disconnected and vulnerable. **GuardianBridge was built to solve this problem.**

It acts as a resilient communication hub, ensuring that even when all other systems are down, your community can stay informed, connected, and coordinated. It's more than just a tool; it's a lifeline that provides critical information and a means of contact, empowering neighborhoods to support each other through any crisis. When connected to a satellite internet provider like Starlink, it remains resilient to local terrestrial infrastructure damage, as satellite internet often stays online when cable and cellular go dark.

## Table of Contents

  * 1.  What's New in GuardianBridge
  * 1.  What is GuardianBridge?
  * 2.  System Philosophy
  * 3.  Core Capabilities
  * 4.  Functionality Deep-Dive
  * 5.  The Admin Panel
  * 6.  Installation & Setup
  * 7.  User & Admin Guides
  * 8.  System Architecture
  * 9.  File Structure
  * 10. Troubleshooting
  * 11. Project Roadmap

## 1. What's New in GuardianBridge

### **GuardianBridge v1.3 "Dispatch"**
This update transforms the SOS system into a true multi-incident command platform, giving administrators, responders, and users the tools they need to manage chaos with clarity.

This release focuses on three core areas: providing peace of mind for those in distress, empowering responders with advanced coordination tools, and giving administrators situational awareness.

#### **1. For You and Your Family: A Personalized Safety Net**
In an emergency, knowing you've been heard and that help is on the way is everything. These features are designed to provide that peace of mind.
* **Immediate Confirmation & Updates:** The moment you send an SOS, the system confirms it has been received. As responders begin to move, you'll get real-time updates with a growing list of names, so you know exactly who is coming to help.
* **New Profile Fields for Critical Info:** In the Admin Panel, you can now add two new crucial pieces of information to your user profile:
    * **Emergency Point of Contact / Next of Kin:** A dedicated field to store information for responders, such as a spouse's contact info, a neighbor's name, or critical medical notes.
    * **SOS Notify List:** This powerful new field allows you to create a custom notification list. You can add a comma-separated list of **email addresses, node IDs, or GuardianBridge usernames**. When you trigger an SOS, the system will send the full alert not only to the official tagged responders but also to every contact on your personal list, ensuring your family and friends are immediately notified.

#### **2. For Responders: A Conversational Interface for a Crisis**
What happens when you send `RESPONDING` and there are three active emergencies? The gateway will now ask you which one you're heading to.
1.  **Step 1:** You send `RESPONDING` as a Direct Message to the gateway.
2.  **Step 2:** The gateway instantly replies with a numbered list of active incidents:
    ```
    Multiple active alerts. Reply with command and number (e.g., ACK 2):
    1. SOSM from Alice
    2. SOSF from David
    ```
3.  **Step 3:** You commit to a specific incident by replying with the command and number: `RESPONDING 1`.

The system then logs you as responding to Alice's alert, notifies the admin, and updates all other responders. This simple, conversational system makes it easy to coordinate even when the situation is complex.

#### **3. For Administrators: The Incident Command Dashboard**
Your "Live Node List" is no longer just a list; during a crisis, it becomes a true **Incident Command Dashboard**.

When multiple SOS alerts are active, the list automatically reorganizes itself, grouping responders and acknowledgers directly under the specific incident they've committed to. This provides an instant, at-a-glance "order of battle" for the entire situation.
* **SOS Sender 1 (Alice)** - Highlighted in Red
    * *SOS Message: "Need medical assistance for injured dog"*
    * **Bob (Responding)** - Highlighted in Green
    * **Charlie (Acknowledged)** - Highlighted in Yellow
* **SOS Sender 2 (David)** - Highlighted in Red
    * *SOS Message: "Smoke visible from my location"*
* **Other Network Nodes...**

This hierarchical view gives you immediate, critical situational awareness, allowing you to see which incidents are being handled and which still need resources.

---

### **GuardianBridge v1.2 "Lifeline Lookout"**
This major update transformed our SOS system into a more responsive, semi-automated emergency communication platform built to keep communities connected when it matters most.

#### **1. For the Person in Distress: Peace of Mind in Seconds**
In an emergency, the scariest moment is wondering if your call for help even got through. Lifeline Lookout removes that uncertainty:
* **Instant Confirmation:** The moment you send an SOS, the system alerts your response team *and* sends you an immediate confirmation:
    ```
    🤖 Your SOSM has been received. Alerting assigned personnel.
    ```
    Now you know for sure that help is on the way.
* **Multi-Responder Updates:** Emergencies often require more than one responder. As each team member sends `RESPONDING`, you see a running list of names:
    * *First responder:* `🤖 Help is on the way. Alice is responding to your alert.`
    * *Second responder:* `🤖 Help is on the way. Alice and Bob are now responding to your alert.`
* **SOS with Context:** A message is good. A message with context saves lives. Add a short note to your SOS—for example:
    ```
    SOSM Need medical assistance for injured dog
    ```
    Responders see this first, giving them vital information before they arrive.

#### **2. For Responders & Admins: Clear, Coordinated Response**
To prevent confusion and overlap, Lifeline Lookout adds new tools for response teams:
* **Team-Based Response:** Multiple responders can now send `RESPONDING`, with each update shared to all team members so everyone knows who’s on the way.
* **Incident Command Dashboard:** In the Admin Panel, the “Live Node List” now transforms during an SOS:
    * SOS sender: Top of the list, in red
    * Responders: Grouped below, in green
    * Acknowledged-but-not-responding members: Grouped in yellow

This gives admins a clear, real-time view of the entire situation.

#### **3. For System Resilience: Built-In Safety Nets**
Emergencies can escalate quickly. Lifeline Lookout includes features to keep help moving even when things go wrong:
* **Active Check-In (Dead Man’s Switch):** The system periodically pings the person in distress. If there’s no response after multiple attempts, it automatically escalates the alert with an **UNRESPONSIVE** status for all responders.
* **No-Response Escalation:** If no tagged responders acknowledge an alert within a set time, the system automatically rebroadcasts the SOS to the entire network, ensuring no one is left behind.

---

## 1\. What is GuardianBridge?

GuardianBridge is a complete, self-contained communication gateway system. It leverages the power of LoRa (Long Range) mesh networking through the Meshtastic platform to create an independent, resilient communication network that your community builds and owns.

### The Power of LoRa and Meshtastic

Meshtastic is an open-source project that uses inexpensive LoRa radios for long-range, off-grid communication. It is designed for scenarios where traditional communication infrastructure is unavailable or unreliable.

  * **Mesh Network Resilience**: Every node in the network acts as a mini-repeater, letting messages hop across devices to route around obstacles or signal failures. This creates a self-healing mesh that routes messages around obstacles or failed nodes, ensuring every member of the group can receive messages.
  * **Decentralized and Off-Grid**: The network operates without any reliance on cell towers, internet providers, or a dedicated central router. This makes it ideal for communication in remote areas or during emergencies.
  * **Accessible & Low-Power**: The system is designed to run 24/7 on affordable, low-power hardware like a Raspberry Pi. A typical Meshtastic node can be built from low-cost components, making it easy to build and expand a community network.
  * **User-Friendly App**: The free Meshtastic app for Android and iOS connects to the LoRa modules via Bluetooth and provides a familiar text-messaging-like interface, making it easy for anyone to use.
  * **Encrypted Communication**: Messages sent over the network are encrypted to ensure privacy and security.

## 2\. System Philosophy

This project is built on three core principles:

1.  **Resilience over Speed**: The system is designed to be fault-tolerant. Its modular architecture ensures that a failure in one component (like fetching email) will not crash the core radio dispatcher. This makes it reliable for long-term, unattended operation in potentially unstable conditions.
2.  **Modularity and Simplicity**: Each major function is handled by a separate, simple script. This makes the system easier to understand, maintain, and extend. Communication via the file system is a deliberate choice to decouple the components, allowing them to work independently.
3.  **Efficiency for Low-Power Devices**: The gateway is optimized to run 24/7 on single-board computers like the Raspberry Pi. The use of an event-driven architecture (`watchdog`) instead of constant polling minimizes unnecessary CPU cycles and disk I/O, respecting the resource constraints of such devices.

## 3\. Core Capabilities

GuardianBridge provides a rich set of automated and on-demand features to keep your community safe and informed.

  * **Automated Weather & Forecasts**: Receive periodic updates on current weather conditions and scheduled daily forecasts directly on your Meshtastic device.
  * **Critical NWS Alerts**: Get timely, automated alerts from the National Weather Service, including warnings for tornadoes, floods, and other severe events.
  * **Two-Way Email Gateway**: A user can send an email from the mesh with a simple command. Conversely, an external user can send an email to the gateway's address, and the message is relayed to the intended mesh user.
  * **Email-Based Broadcasts**: Authorized administrators can send network-wide broadcast messages simply by sending an email with the subject line `broadcast` or `!broadcast` (for an audible alert).
  * **Tag-Based Group Messaging**: Assign tags (e.g., `CERT`, `MEDICAL`) to users to create logical groups. Admins and authorized users can then send targeted messages to these groups via email or from their node.
  * **Flexible Scheduled Broadcasts**: The administrator can configure custom, recurring messages or one-time event announcements to be broadcast on a fine-grained schedule using the Admin Panel.
  * **User Self-Service**: Users can subscribe, unsubscribe, register a name, and toggle individual broadcast types using simple direct messages to the gateway.
  * **SOS Emergency Alert System**: Users can trigger an alert (general, police, fire, medical) and admins can manage the response, including remote clearance.
  * **Satellite-Resilient**: When the gateway server is connected to a satellite internet provider like Starlink, it remains resilient to local terrestrial infrastructure damage, as satellite internet often stays online when cable and cellular go dark.

## 4\. Functionality Deep-Dive

#### Weather & NWS Alerts

The `weather_fetcher.py` script uses your configured `LATITUDE` and `LONGITUDE` to find the nearest NWS grid point and observation station. It fetches data and saves it locally. This minimizes external API calls and allows the gateway to function even if the internet connection is temporarily lost, broadcasting the last known data. The `meshtastic_dispatcher.py` checks these files at intervals defined in the `.env` file and broadcasts to all subscribed users.

#### Two-Way Email Gateway

  * **Sending (Mesh -\> Email)**: A user sends a DM to the gateway: `email/recipient@domain.com/Subject/Body`. The dispatcher writes this task to `data/outgoing_emails.json`. The `email_processor.py` cron job picks it up, sends the email, and includes a helpful footer explaining how to reply.
  * **Receiving (Email -\> Mesh)**: A person sends an email to the gateway's address. The system uses a 4-tier logic to find the recipient:
    1.  It first checks the subject line for a node ID (e.g., `!a1b2c3d4`) or registered name.
    2.  If not found, it checks the full "To:" header for a node ID.
    3.  If not found, it checks the email body for the "sent the following message:" watermark from a previous reply.
    4.  As a last resort, it scans the entire email body for any node ID.
        The `email_processor.py` script then intelligently strips the original message from the reply and creates a command file in `data/commands/`. The dispatcher instantly detects this new file and sends the message to the correct node.
  * **Broadcast (Email -\> Mesh)**: An authorized admin sends an email to the gateway's address with the subject `broadcast`. The system verifies the sender's permissions, prefixes the message with "FM [Admin Name]:", and broadcasts it to the entire network. A confirmation or rejection email is automatically sent back to the sender. If the subject is `!broadcast` or `broadcast!`, an audible bell character is prepended to the message for an alert.

#### Tag-Based Group Messaging

This powerful feature allows for targeted communication to specific groups. Tags (e.g., `CERT`, `MEDICAL`) are assigned to users by an administrator in the web panel. This provides a secure way to manage group membership.

  * **Email to Tag Group**: An authorized user can send a message to all members of one or more groups by sending an email to the gateway address with a subject like `Tag CERT MEDICAL`. The system finds all users who have either the `CERT` or `MEDICAL` tag and relays the email body to them.
  * **Node to Tag Group**: A user with the "Node Tag Send" permission (granted by an admin) can send a message directly from their device to a tag group using the `tagsend` command.

#### Flexible Scheduled Broadcasts

The `data/dispatcher_jobs.json` file holds a JSON array of broadcast jobs. This allows for complex scheduling without modifying code. The dispatcher checks this file every minute and evaluates each job's rules (`days`, `start_time`, `stop_time`, `interval_mins`) to see if a broadcast is due. It tracks the `last_sent` timestamp within the file itself to ensure it respects the specified interval.

#### SOS Emergency Alert System

A comprehensive SOS system allows users to signal for help and administrators to manage the response.

  * **User Commands**: Users trigger alerts by sending `SOS` (general), `SOSP` (police), `SOSF` (fire), or `SOSM` (medical) as a Direct Message to the gateway. To cancel, they send `CLEAR`, `CANCEL`, or `SAFE`.
  * **Backend Automation**: Upon receiving an SOS, the `meshtastic_dispatcher.py` immediately requests a fresh location update from the user's node. The event is logged in `sos_log.json` for persistent record-keeping. The alert is relayed as a high-priority DM to subscribed users with corresponding "responder" tags, including the sender's name and last known location with a map link.
  * **Active Status**: A user's active SOS status is recorded in `node_status.json`, persisting even if the node goes offline.
  * **Admin Clearance**: Administrators can remotely clear an active SOS using the "Admin Clear SOS" button in the web UI. This sends a "STAND DOWN" message to responders and clears the SOS status.

## 5\. The GuardianBridge Admin Panel

The Admin Panel (`map.php`) provides a comprehensive, web-based user interface for managing and monitoring the entire GuardianBridge system. From this single-page dashboard, you can check system health, manually trigger actions, manage users, create complex scheduled broadcasts, and modify core system settings without ever needing to touch the command line.

#### Functional Guide by Tab

  * **Status Tab**: Your main dashboard for monitoring the gateway's health, including service status (active/inactive), radio connection, and the last time the cron jobs for weather and email ran. It features a live map and node list that automatically refreshes every 5 seconds by fetching data from `api_get_nodes.php`. Nodes with an active SOS are highlighted with a distinct red icon on the map and in the node list.
  * **Chat Tab**: Provides a real-time interface for monitoring and participating in mesh network conversations, polling for updates. You can broadcast messages to the main channel or send Direct Messages (DMs) to a specific user. Filters allow you to selectively show or hide Direct Messages and system-generated server messages. Clicking a user's Node ID opens a dedicated DM chat modal for private conversations.
  * **Actions Tab**: Allows you to perform manual tasks like forcing an immediate weather fetch or email processing cycle. You can also view and clear the queue of outgoing emails and the queue for failed direct messages. A new "SOS Alert Log" displays a full history of all received SOS alerts.
  * **Broadcasts Tab**: A powerful interface for managing custom, automated messages. You can create recurring jobs (e.g., a "Good Morning" message every weekday) or one-time announcements for a specific date and time range.
  * **Users Tab**: Provides full control over subscribers. You can edit user names, full names, phone numbers, email, addresses, and notes. You can toggle individual subscriptions (alerts, weather, forecast) and manage advanced permissions like email send/receive/broadcast and node tag send. You can also manage assigned tags and set a "blocked" status to ignore all commands from a specific user. The tab displays both the assigned role and the live reported role from the node's radio, highlighting discrepancies.
  * **Settings Tab**: Allows for easy editing of the system's core configuration file (`.env`). This is where you can change GPS coordinates, email credentials, or broadcast intervals. **Remember to restart the dispatcher service after saving\!**
  * **Help/About Tab**: Contains this detailed system documentation and version information.

## 6\. Installation & Setup

This guide walks you through the complete setup for both the backend services and the web admin panel.

### Prerequisites

  * A Linux server (Raspberry Pi OS recommended) with Python 3.9+ and Git.
  * A Meshtastic device (e.g., Heltec ESP32) connected to the server via USB.
  * A web server with PHP support (e.g., Apache2, Nginx). The `shell_exec` function must be enabled in PHP.
  * An email account for the gateway (a Gmail account with a 16-digit App Password is recommended).

### Step 1: Install Backend Services

1.  **Clone the repository and move it to the recommended directory:**
    ```bash
    git clone <your-repository-url> ~/guardian-bridge
    sudo mv ~/guardian-bridge /opt/GuardianBridge
    ```
2.  **Create data directories and set ownership:**
    ```bash
    sudo mkdir -p /opt/GuardianBridge/data/commands
    sudo chown -R pi:pi /opt/GuardianBridge 
    cd /opt/GuardianBridge
    ```
    *Replace `pi:pi` with your user and group if different.*
3.  **Install Python dependencies:**
    ```bash
    pip3 install -r requirements.txt
    ```

### Step 2: Install Web Admin Panel

1.  **Install a web server if you don't have one:**
    ```bash
    sudo apt-get update
    sudo apt-get install apache2 php libapache2-mod-php -y
    ```
2.  **Place the admin panel file in the web root:**
    ```bash
    sudo cp /path/to/your/map.php /var/www/html/index.php
    ```
    *Renaming it to `index.php` makes it the default page when you navigate to the server's IP address.*
3.  **Set crucial file permissions for the web server:** This is the most critical step. The web server user (`www-data`) needs to be able to write to the project directory.
    ```bash
    sudo usermod -a -G www-data pi
    sudo chown -R pi:www-data /opt/GuardianBridge
    sudo chmod -R 775 /opt/GuardianBridge
    ```
    **A system reboot or logging out and back in** is required for the group change to take effect.

### Step 3: Configure the System

1.  **Create the `.env` file from the template:** `cp .env.txt .env`
2.  **Edit the `.env` file** (`nano .env`) with your specific details (GPS coordinates, email credentials, etc.). You can also edit this later from the Admin Panel's "Settings" tab.
3.  **Set a secure Admin Password:**
      * Create a temporary PHP file (e.g., `hash_gen.php`) in your web directory with the content: `<?php echo password_hash('YourNewPassword', PASSWORD_DEFAULT); ?>`
      * Access this file in your browser, copy the resulting hash string.
      * Open `map.php` (now at `/var/www/html/index.php`) and replace the example hash in the `$admin_password_hash` variable with your new one.

### Step 4: Enable and Start Services

1.  **Create and enable the dispatcher service.** Create the file `sudo nano /etc/systemd/system/guardianbridge.service` with the following content:
    ```bash
    [Unit]
    Description=Meshtastic Dispatcher Service
    After=network.target
    
    [Service]
    Type=simple
    User=pi
    Group=pi
    WorkingDirectory=/opt/GuardianBridge
    ExecStart=/usr/bin/python3 /opt/GuardianBridge/meshtastic_dispatcher.py
    Restart=on-failure
    RestartSec=10
    
    [Install]
    WantedBy=multi-user.target
    ```
2.  **Enable and start the service:**
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable guardianbridge.service
    sudo systemctl start guardianbridge.service
    ```
3.  **Set up Cron Jobs** for periodic tasks by editing the crontab (`crontab -e`):
    ```bash
    # Fetch weather data every 15 minutes
    */15 * * * * /usr/bin/python3 /opt/GuardianBridge/weather_fetcher.py >> /opt/GuardianBridge/data/cron.log 2>&1
    
    # Process incoming and outgoing emails every 5 minutes
    */5 * * * * /usr/bin/python3 /opt/GuardianBridge/email_processor.py >> /opt/GuardianBridge/data/cron.log 2>&1
    ```

## 7\. User & Admin Guides

### End-User Guide (Interacting via Meshtastic)

Interact with the GuardianBridge gateway by sending it Direct Messages from your Meshtastic device.

#### Subscription & Status Commands

| Command | Description |
| :--- | :--- |
| `help` or `?` | Shows a list of available commands. |
| `subscribe` | Subscribes you to all automated broadcasts. |
| `unsubscribe` | Unsubscribes you from all broadcasts. |
| `status` | Shows your current name, subscription settings, and assigned tags. |
| `alerts on/off` | Toggles NWS weather alerts. |
| `weather on/off`| Toggles periodic current weather updates. |
| `forecasts on/off`| Toggles scheduled daily forecasts. |

#### On-Demand, Group & Email Commands

| Command | Description |
| :--- | :--- |
| `wx` | Instantly fetches the current or next upcoming forecast. |
| `name/YourName` | Registers or updates your display name. Must be a single word. Ex: `name/John` |
| `email/to/subj/body` | Sends an email. Ex: `email/friend@test.com/Mesh Msg/Hello from the field!` |
| `tagsend/tags/msg`| Sends a message to a tag group. Ex: `tagsend/CERT/Meeting at 5`. *Requires admin-granted permission.* |
| `SOS`, `SOSP`, `SOSF`, `SOSM` | Triggers an emergency alert (General, Police, Fire, Medical). |
| `CLEAR`, `CANCEL`, `SAFE` | Clears your active emergency alert. |

### Authorized User Guide (Using Email Features)

#### Sending a Message to a Mesh User (Email Relay)

To send a message from your email account to a specific user on the Meshtastic network, compose a new email and include the user's Node ID or registered name in the subject line.

  * **To:** `your-gateway-email@example.com`
  * **Subject:** `For !a1b2c3d4, Meeting Update`
  * The body of your email will be delivered to the user.

#### Sending a Message to a Tag Group

To send a message to a group of users based on their assigned tags, compose a new email with the word `Tag` followed by the tag names in the subject line.

  * **To:** `your-gateway-email@example.com`
  * **Subject:** `Tag CERT MEDICAL`
  * The body of your email will be delivered to all users with either the `CERT` or `MEDICAL` tag. You will receive an email confirming that your message was relayed.

#### Sending a Network-Wide Broadcast (Admins Only)

If you have been granted broadcast permission, you can send a message to all users on the network directly from your email client.

  * **To:** `your-gateway-email@example.com`
  * **Standard Broadcast Subject:** `Broadcast`
  * **Alert Broadcast Subject:** `!broadcast` or `broadcast!` (This prepends an audible bell character to the message).
  * The body of your email will be sent to every node. You will receive an email confirming that your broadcast was sent or informing you if you are not authorized.

## 8\. System Architecture

The system's stability comes from its modular design, where tasks are separated into distinct, independent scripts. The components communicate via a simple and robust file-based system centered around the `data/` directory. This prevents an error in one part of the system (like email fetching) from crashing another.

  * **`meshtastic_dispatcher.py`**: The core service that runs persistently. It listens for commands from users, sends messages, manages all scheduled broadcasts (weather, alerts, custom), and uses the `watchdog` library to instantly detect and process new command files. It also handles SOS alerts, requests location updates, and retries failed direct messages from a queue.
  * **`weather_fetcher.py`**: A cron job that fetches data from the NWS API (current conditions, forecasts, alerts) and saves it to JSON files in the `data/` directory for the dispatcher to read and display.
  * **`email_processor.py`**: A cron job that handles both sending and receiving emails. It reads outgoing requests from `outgoing_emails.json` and writes incoming messages as command files (`relay` or `broadcast`) for the dispatcher to process. It uses a 4-tier logic to find the intended mesh recipient.
  * **Admin Panel (`map.php`)**: The web interface. When an admin performs an action like sending a broadcast or a DM, the PHP script writes a small JSON file into the `data/commands/` directory.
  * **The `data/` Directory**: This folder acts as the central message queue between the web panel, the email processor, and the main dispatcher. The dispatcher is always "watching" this folder, so when a new command file or a change to `subscribers.json` appears, it immediately processes it. This ensures a decoupled but fully integrated control system.

## 9\. File Structure

All files are located within the `/opt/GuardianBridge/` directory.

```
/opt/GuardianBridge/
├── meshtastic_dispatcher.py # Main service, always running
├── email_processor.py       # Handles email I/O (cron job)
├── weather_fetcher.py       # Fetches NWS data (cron job)
├── settings.py              # Loads settings from .env
├── requirements.txt         # Python dependencies
├── .env                     # User-specific secrets and settings
└── data/                    # Directory for all runtime data
    ├── subscribers.json     # List of users, their settings, assigned tags, and permissions
    ├── outgoing_emails.json # Queue for emails to be sent
    ├── failed_dm_queue.json # Queue for failed Direct Messages
    ├── weather_current.json # Latest weather observation from NWS
    ├── weather_forecast.json# Latest multi-day forecast from NWS
    ├── nws_alerts.json      # Current active NWS alerts
    ├── dispatcher_jobs.json # Schedule for custom broadcasts, managed by the web panel
    ├── dispatcher_state.json# Stores last-sent times for scheduled broadcasts
    ├── dispatcher_status.json# Health status for the web panel
    ├── node_status.json     # Stores active status for nodes (e.g., SOS state)
    ├── channel0_log.json    # Log of all chat messages for the web panel
    ├── sos_log.json         # New file for SOS logging
    ├── *.lastrun            # Files indicating cron jobs ran
    └── commands/            # Folder for command files (the message bus)
        └── error/           # Quarantined/malformed command files
```

## 10\. Troubleshooting

  * **Gateway is not responding**: Check the service status with `sudo systemctl status guardianbridge.service`. Look at the logs with `journalctl -u guardianbridge.service -f` for errors. Ensure the Meshtastic device is powered and connected.
  * **Weather is not updating**: Run `python3 /opt/GuardianBridge/weather_fetcher.py` manually and check for errors. Check that the `data/weather_fetcher.lastrun` file has a recent timestamp. Ensure your `LATITUDE` and `LONGITUDE` in the `.env` file are correct.
  * **Emails are not being sent/received**: Run `python3 /opt/GuardianBridge/email_processor.py` manually. Check for authentication errors and ensure you are using a correct App Password for Gmail. Check the `data/email_processor.lastrun` file timestamp.
  * **Broadcast email failed**: If you receive a rejection email, check the `subscribers.json` file to ensure your email address is listed for a user and that their `"emailbroadcast": true` flag is set.
  * **Admin Panel shows "failed to write" or "not readable" errors**: This is almost always a file permissions issue. Ensure the web server user (`www-data`) has write access to the `/opt/GuardianBridge/` directory and its contents. Refer to the installation steps.
  * **A user is blocked/unblocked, but it doesn't take effect**: This can happen if the `watchdog` library isn't working correctly. Restart the dispatcher service (`sudo systemctl restart guardianbridge.service`) to force it to reload the `subscribers.json` file.
  * **Settings changed in panel but not taking effect**: You must restart the main dispatcher service after saving changes to the `.env` file: `sudo systemctl restart guardianbridge.service`.
  * **SOS alert not clearing or not being received by responders**: Verify the node's `sos` status in `node_status.json`. Ensure responders have the correct tags assigned in `subscribers.json`. Check dispatcher logs for errors during SOS processing or message sending. If an admin clear command was used, verify it was queued and processed in the `commands/` directory.

## 11\. Project Roadmap

This project is in active development. Future enhancements being considered include:

  * **Direct SAME/EAS Integration**: Ingesting alert streams directly from NOAA Weather Radio broadcasts for ultimate redundancy, providing a layer of protection that does not depend on any internet connection.
  * **Canned Status Messages**: Implementing quick commands for users to broadcast their status (e.g., "I'm OK," "Need Assistance," "Have Supplies") for rapid community check-ins during an emergency.