import importlib.util
import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from datetime import datetime, timedelta, tzinfo


def _install_stub(module_name, module_obj):
    sys.modules[module_name] = module_obj


def _install_stubs():
    # dotenv
    dotenv = types.ModuleType("dotenv")
    dotenv.load_dotenv = lambda *args, **kwargs: None
    _install_stub("dotenv", dotenv)

    # tzlocal
    tzlocal = types.ModuleType("tzlocal")
    tzlocal.get_localzone_name = lambda: "UTC"
    _install_stub("tzlocal", tzlocal)

    # pytz
    class DummyTZ(tzinfo):
        def utcoffset(self, dt):
            return timedelta(0)

        def dst(self, dt):
            return timedelta(0)

        def tzname(self, dt):
            return "UTC"

        def localize(self, dt):
            return dt.replace(tzinfo=self)

    pytz = types.ModuleType("pytz")
    pytz.UTC = DummyTZ()
    pytz.timezone = lambda name: DummyTZ()
    _install_stub("pytz", pytz)

    # meshtastic and submodules
    meshtastic = types.ModuleType("meshtastic")
    meshtastic.MeshtasticException = Exception
    _install_stub("meshtastic", meshtastic)

    meshtastic_serial = types.ModuleType("meshtastic.serial_interface")
    class DummySerialInterface:
        pass
    meshtastic_serial.SerialInterface = DummySerialInterface
    _install_stub("meshtastic.serial_interface", meshtastic_serial)

    meshtastic_protobuf = types.ModuleType("meshtastic.protobuf")
    _install_stub("meshtastic.protobuf", meshtastic_protobuf)

    config_pb2 = types.ModuleType("meshtastic.protobuf.config_pb2")
    class DummyRole:
        @staticmethod
        def Name(val):
            return "UNKNOWN"
    class DummyDeviceConfig:
        Role = DummyRole
    class DummyConfig:
        DeviceConfig = DummyDeviceConfig
    config_pb2.Config = DummyConfig
    _install_stub("meshtastic.protobuf.config_pb2", config_pb2)

    # pubsub
    pubsub = types.ModuleType("pubsub")
    class DummyPub:
        def subscribe(self, *args, **kwargs):
            return None
    pubsub.pub = DummyPub()
    _install_stub("pubsub", pubsub)


def _import_dispatcher():
    _install_stubs()
    repo_root = Path(__file__).resolve().parents[1]
    dispatcher_path = repo_root / "meshtastic_dispatcher.py"
    spec = importlib.util.spec_from_file_location("meshtastic_dispatcher", dispatcher_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["meshtastic_dispatcher"] = module
    spec.loader.exec_module(module)
    return module


class DispatcherTests(unittest.TestCase):
    def _reset_db(self):
        self.dispatcher.gb_db._initialized = False
        if os.path.exists(self.dispatcher.settings.DB_PATH):
            os.remove(self.dispatcher.settings.DB_PATH)

    def setUp(self):
        self.dispatcher = _import_dispatcher()
        self.temp_dir = tempfile.TemporaryDirectory()

        self.dispatcher.settings.DATA_DIR = self.temp_dir.name
        self.dispatcher.settings.SUBSCRIBERS_FILE = os.path.join(self.temp_dir.name, "subscribers.json")
        self.dispatcher.settings.NODE_STATUS_FILE = os.path.join(self.temp_dir.name, "node_status.json")
        self.dispatcher.settings.SOS_LOG_FILE = os.path.join(self.temp_dir.name, "sos_log.json")
        self.dispatcher.settings.CHANNEL0_LOG_FILE = os.path.join(self.temp_dir.name, "channel0_log.json")
        self.dispatcher.settings.DB_PATH = os.path.join(self.temp_dir.name, "guardianbridge.db")
        self.dispatcher.settings.OUTGOING_EMAIL_FILE = os.path.join(self.temp_dir.name, "outgoing_emails.json")
        self.dispatcher.settings.WEATHER_CURRENT_FILE = os.path.join(self.temp_dir.name, "weather_current.json")
        self.dispatcher.settings.WEATHER_FORECAST_FILE = os.path.join(self.temp_dir.name, "weather_forecast.json")
        self.dispatcher.settings.WEATHER_ALERTS_FILE = os.path.join(self.temp_dir.name, "nws_alerts.json")
        self.dispatcher.settings.DISPATCHER_STATE_FILE = os.path.join(self.temp_dir.name, "dispatcher_state.json")
        self.dispatcher.settings.DISPATCHER_STATUS_FILE = os.path.join(self.temp_dir.name, "dispatcher_status.json")
        self.dispatcher.settings.DISPATCHER_JOBS_FILE = os.path.join(self.temp_dir.name, "dispatcher_jobs.json")
        self.dispatcher.settings.FAILED_DM_QUEUE_FILE = os.path.join(self.temp_dir.name, "failed_dm_queue.json")
        self.dispatcher.settings.EMAIL_BLOCKLIST_FILE = os.path.join(self.temp_dir.name, "email_blocklist.json")
        self.dispatcher.settings.BASE_DIR = self.temp_dir.name
        self.dispatcher.settings.AUTO_BACKUP_DIR = os.path.join(self.temp_dir.name, "AutoBackUp")
        self.dispatcher.settings.WEATHER_UPDATE_INTERVAL_MINS = 30
        self.dispatcher.settings.WEATHER_ALERT_INTERVAL_MINS = 15
        self.dispatcher.settings.SOS_ACK_TIMEOUT_MINS = 5
        self.dispatcher.settings.SOS_CHECKIN_INTERVAL_MINS = 5
        self.dispatcher.settings.SOS_CHECKIN_MAX_ATTEMPTS = 3
        self.dispatcher.settings.TEMP_GROUP_TTL_DAYS = 14
        self.dispatcher.settings.FORECAST_SEND_TIMES = ["07:00", "19:00"]

        os.makedirs(self.dispatcher.settings.AUTO_BACKUP_DIR, exist_ok=True)
        self.dispatcher.gb_db._initialized = False
        self.dispatcher.gb_db.ensure_db()
        self.dispatcher.core.dispatcher_state = {}
        self.dispatcher.core.broadcasted_alert_headlines = set()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_command_text_preserves_args_case(self):
        command, args = self.dispatcher.parse_command_text("Name/John Doe")
        self.assertEqual(command, "name")
        self.assertEqual(args, "John Doe")

        command, args = self.dispatcher.parse_command_text("EMAIL/user@example.com/Subject Case/Body MIXED")
        self.assertEqual(command, "email")
        self.assertEqual(args, "user@example.com/Subject Case/Body MIXED")

    def test_cmd_send_email_requires_permission(self):
        sender_id = "!aaaa1111"
        self.dispatcher.core.subscribers = {
            sender_id: {"email_send": False}
        }

        resp = self.dispatcher._cmd_send_email(sender_id, "to@x.com/Subject/Body")
        self.assertEqual(resp, "You are not authorized to send emails.")

        self.dispatcher.core.subscribers[sender_id]["email_send"] = True
        resp = self.dispatcher._cmd_send_email(sender_id, "to@x.com/Subject/Body")
        self.assertIsNone(resp)

        queued = self.dispatcher.gb_db.fetch_outgoing_emails()
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["subject"], "Subject")
        self.assertEqual(queued[0]["body"], "Body")

    def test_hi_command_returns_server_time_weather_and_forecast(self):
        sender_id = "!hello1001"
        self.dispatcher.settings.SERVER_NAME = "TestBridge"
        self.dispatcher.settings.SERVER_VERSION = "v9.9.9"

        with open(self.dispatcher.settings.WEATHER_CURRENT_FILE, "w") as f:
            json.dump({"temperature_f": 72, "humidity": 44}, f)

        original_forecast = self.dispatcher.commands.get_current_forecast_message
        self.dispatcher.commands.get_current_forecast_message = lambda: "🔮 Tonight: Clear, 61°F"

        sent = []
        self.dispatcher.commands.send_meshtastic_message = lambda text, **kwargs: sent.append((text, kwargs))

        try:
            self.dispatcher.commands.handle_meshtastic_command(sender_id, "Hi")
        finally:
            self.dispatcher.commands.get_current_forecast_message = original_forecast

        self.assertTrue(sent)
        combined_text = "\n".join(msg[0] for msg in sent)
        self.assertIn("TestBridge v9.9.9", combined_text)
        self.assertIn("Time:", combined_text)
        self.assertIn("Currently: 72°F, 44%RH", combined_text)
        self.assertIn("Tonight: Clear, 61°F", combined_text)
        self.assertTrue(all(msg[1].get("destinationId") == sender_id for msg in sent))

    def test_parse_command_text_accepts_trailing_question_mark(self):
        command, args = self.dispatcher.parse_command_text("Hello?")
        self.assertEqual(command, "hello")
        self.assertEqual(args, "")

        command, args = self.dispatcher.parse_command_text("Hi?")
        self.assertEqual(command, "hi")
        self.assertEqual(args, "")

        command, args = self.dispatcher.parse_command_text("?")
        self.assertEqual(command, "?")
        self.assertEqual(args, "")

    def test_process_queued_broadcast_command(self):
        sent = []
        def fake_send(text, **kwargs):
            sent.append((text, kwargs))
        self.dispatcher.commands.send_meshtastic_message = fake_send

        self.dispatcher.gb_db.enqueue_command_job(
            {"command": "broadcast", "text": "hello"},
            source_file="test:broadcast",
        )
        self.dispatcher.commands.process_command_jobs(max_jobs=5)

        self.assertTrue(any(msg[0] == "hello" for msg in sent))

    def test_sqlite_does_not_migrate_from_json(self):
        subscribers = {"!abc": {"name": "Alice"}}
        node_status = {"!abc": {"sos": "SOS"}}
        channel_log = [{"from": "!abc", "timestamp": "12:00 01/01", "text": "hi"}]
        sos_log = [{"node_id": "!abc", "active": True}]

        with open(self.dispatcher.settings.SUBSCRIBERS_FILE, "w") as f:
            json.dump(subscribers, f)
        with open(self.dispatcher.settings.NODE_STATUS_FILE, "w") as f:
            json.dump(node_status, f)
        with open(self.dispatcher.settings.CHANNEL0_LOG_FILE, "w") as f:
            json.dump(channel_log, f)
        with open(self.dispatcher.settings.SOS_LOG_FILE, "w") as f:
            json.dump(sos_log, f)

        self._reset_db()
        self.dispatcher.gb_db.ensure_db()

        loaded_subs = self.dispatcher.gb_db.load_subscribers_dict()
        self.assertEqual(loaded_subs, {})

        loaded_nodes = self.dispatcher.gb_db.load_node_statuses_dict()
        self.assertEqual(loaded_nodes, {})

        messages, last_id = self.dispatcher.gb_db.get_chat_logs()
        self.assertEqual(len(messages), 0)
        self.assertEqual(last_id, 0)

        sos_entries = self.dispatcher.gb_db.load_sos_logs()
        self.assertEqual(len(sos_entries), 0)

    def test_handle_sos_alert_creates_log_and_status(self):
        sender_id = "!aaaa1111"
        self.dispatcher.core.subscribers = {sender_id: {"name": "Alice"}}

        sent = []
        self.dispatcher.sos.send_meshtastic_message = lambda text, **kwargs: sent.append((text, kwargs))
        self.dispatcher.sos.queue_sos_email_notification = lambda *args, **kwargs: None
        self.dispatcher.core.iface = None

        self.dispatcher.sos.handle_sos_alert(sender_id, "SOSM", "Need help")

        logs = self.dispatcher.gb_db.load_active_sos_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["node_id"], sender_id)
        self.assertEqual(logs[0]["sos_type"], "SOSM")

        status = self.dispatcher.gb_db.get_node_status(sender_id)
        self.assertEqual(status.get("sos"), "SOSM")

    def test_handle_sos_ack_and_responding_updates_lists(self):
        sender_id = "!sos1111"
        responder_id = "!resp0001"
        self.dispatcher.core.subscribers = {
            sender_id: {"name": "Alice", "tags": []},
            responder_id: {"name": "Bob", "tags": []},
        }
        self.dispatcher.sos.send_meshtastic_message = lambda *args, **kwargs: None

        entry = {
            "timestamp": datetime.now(self.dispatcher.core.local_tz).isoformat(),
            "sos_type": "SOS",
            "node_id": sender_id,
            "user_info": {"name": "Alice"},
            "active": True,
            "acknowledged_by": [],
            "responding_list": [],
            "last_checkin_time": datetime.now(self.dispatcher.core.local_tz).isoformat(),
            "checkin_attempts": 0,
        }
        self.dispatcher.gb_db.insert_sos_log(entry)

        self.dispatcher.sos.handle_sos_ack(responder_id, sender_id)
        logs = self.dispatcher.gb_db.load_active_sos_logs()
        self.assertIn(responder_id, logs[0]["acknowledged_by"])

        self.dispatcher.sos.handle_sos_responding(responder_id, sender_id)
        logs = self.dispatcher.gb_db.load_active_sos_logs()
        self.assertIn(responder_id, logs[0]["responding_list"])
        self.assertNotIn(responder_id, logs[0].get("acknowledged_by", []))

    def test_multi_incident_sos_selection_routes_ack(self):
        responder_id = "!resp1111"
        sos_one = "!sos0001"
        sos_two = "!sos0002"
        now = datetime.now(self.dispatcher.core.local_tz)

        self.dispatcher.core.subscribers = {
            responder_id: {"name": "Responder", "tags": []},
            sos_one: {"name": "Alice", "tags": []},
            sos_two: {"name": "Bob", "tags": []},
        }

        sent = []
        self.dispatcher.sos.send_meshtastic_message = lambda text, **kwargs: sent.append(text)

        entry_one = {
            "timestamp": now.isoformat(),
            "sos_type": "SOS",
            "node_id": sos_one,
            "user_info": {"name": "Alice"},
            "active": True,
            "acknowledged_by": [],
            "responding_list": [],
            "last_checkin_time": now.isoformat(),
            "checkin_attempts": 0,
            "escalated_no_ack": False,
            "escalated_unresponsive": False,
        }
        entry_two = {
            "timestamp": now.isoformat(),
            "sos_type": "SOSM",
            "node_id": sos_two,
            "user_info": {"name": "Bob"},
            "active": True,
            "acknowledged_by": [],
            "responding_list": [],
            "last_checkin_time": now.isoformat(),
            "checkin_attempts": 0,
            "escalated_no_ack": False,
            "escalated_unresponsive": False,
        }
        self.dispatcher.gb_db.insert_sos_log(entry_one)
        self.dispatcher.gb_db.insert_sos_log(entry_two)

        self.dispatcher.sos.handle_sos_action_initial(responder_id, "ACK")
        self.assertEqual(
            self.dispatcher.core.user_interaction_state.get(responder_id),
            "awaiting_sos_choice",
        )
        self.assertTrue(any("Multiple active alerts" in msg for msg in sent))

        self.dispatcher.sos.handle_sos_choice(responder_id, "ACK", 2)
        logs = self.dispatcher.gb_db.load_active_sos_logs()
        sos_one_log = next(e for e in logs if e.get("node_id") == sos_one)
        sos_two_log = next(e for e in logs if e.get("node_id") == sos_two)
        self.assertNotIn(responder_id, sos_one_log.get("acknowledged_by", []))
        self.assertIn(responder_id, sos_two_log.get("acknowledged_by", []))

    def test_handle_active_sos_tasks_escalates_no_ack(self):
        now = datetime.now(self.dispatcher.core.local_tz)
        self.dispatcher.settings.SOS_ACK_TIMEOUT_MINS = 0
        self.dispatcher.core.subscribers = {"!sos": {"name": "Alice", "tags": []}}

        entry = {
            "timestamp": (now - timedelta(minutes=1)).isoformat(),
            "sos_type": "SOS",
            "node_id": "!sos",
            "user_info": {"name": "Alice"},
            "active": True,
            "acknowledged_by": [],
            "responding_list": [],
            "last_checkin_time": now.isoformat(),
            "checkin_attempts": 0,
            "escalated_no_ack": False,
            "escalated_unresponsive": False,
        }
        self.dispatcher.gb_db.insert_sos_log(entry)

        broadcasts = []
        self.dispatcher.sos.broadcast_to_subscribers = lambda msg, key: broadcasts.append((msg, key))
        self.dispatcher.sos.send_meshtastic_message = lambda *args, **kwargs: None

        self.dispatcher.sos.handle_active_sos_tasks(now)

        logs = self.dispatcher.gb_db.load_active_sos_logs()
        self.assertTrue(logs[0]["escalated_no_ack"])
        self.assertTrue(broadcasts)

    def test_handle_active_sos_tasks_escalates_unresponsive(self):
        now = datetime.now(self.dispatcher.core.local_tz)
        self.dispatcher.settings.SOS_CHECKIN_INTERVAL_MINS = 0
        self.dispatcher.settings.SOS_CHECKIN_MAX_ATTEMPTS = 1

        sender_id = "!sos"
        responder_id = "!resp"
        self.dispatcher.core.subscribers = {
            sender_id: {"name": "Alice", "tags": []},
            responder_id: {"name": "Bob", "tags": ["SOS"]},
        }

        entry = {
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "sos_type": "SOS",
            "node_id": sender_id,
            "user_info": {"name": "Alice"},
            "active": True,
            "acknowledged_by": [],
            "responding_list": [responder_id],
            "last_checkin_time": (now - timedelta(minutes=2)).isoformat(),
            "checkin_attempts": 1,
            "escalated_no_ack": False,
            "escalated_unresponsive": False,
        }
        self.dispatcher.gb_db.insert_sos_log(entry)

        sent = []
        self.dispatcher.sos.send_meshtastic_message = lambda text, **kwargs: sent.append(text)
        self.dispatcher.sos.handle_active_sos_tasks(now)

        logs = self.dispatcher.gb_db.load_active_sos_logs()
        self.assertTrue(logs[0]["escalated_unresponsive"])
        self.assertTrue(any("UNRESPONSIVE" in msg for msg in sent))

    def test_broadcast_subscribers_sends_to_each(self):
        sent = []
        logged = []
        self.dispatcher.commands.send_meshtastic_message = lambda **kwargs: sent.append(kwargs)
        self.dispatcher.core.log_channel_message = lambda sender, text, is_dm=False: logged.append((sender, text, is_dm))
        original_loader = self.dispatcher.commands.gb_db.load_subscribers_dict
        self.dispatcher.commands.gb_db.load_subscribers_dict = lambda: {
            "!a1": {"blocked": False},
            "!b2": {"blocked": True},
            "!c3": {},
        }

        try:
            self.dispatcher.gb_db.enqueue_command_job(
                {"command": "broadcast_subscribers", "text": "Hello all"},
                source_file="test:broadcast_subscribers",
            )
            self.dispatcher.commands.process_command_jobs(max_jobs=5)

            dests = sorted([msg.get("destinationId") for msg in sent])
            self.assertEqual(dests, ["!a1", "!c3"])
            self.assertEqual(len(logged), 1)
            self.assertIn("@all Hello all", logged[0][1])
            self.assertTrue(all(msg.get("suppress_log") for msg in sent))
        finally:
            self.dispatcher.commands.gb_db.load_subscribers_dict = original_loader

    def test_handle_periodic_weather_broadcasts_updates_state(self):
        now = datetime.now(self.dispatcher.core.local_tz)
        self.dispatcher.core.dispatcher_state = {}
        with open(self.dispatcher.settings.WEATHER_CURRENT_FILE, "w") as f:
            json.dump({"temperature_f": 70, "humidity": 50}, f)

        sent = []
        self.dispatcher.weather.broadcast_to_subscribers = lambda msg, key: sent.append((msg, key))
        self.dispatcher.weather.handle_periodic_weather_broadcasts(now, initial_broadcast=True)

        self.assertTrue(sent)
        self.assertIn("last_weather_update", self.dispatcher.core.dispatcher_state)

    def test_handle_daily_forecasts_sets_sent_date(self):
        now = datetime.now(self.dispatcher.core.local_tz)
        time_str = now.strftime("%H:%M")
        self.dispatcher.settings.FORECAST_SEND_TIMES = [time_str]
        period = {
            "startTime": now.isoformat(),
            "endTime": (now + timedelta(hours=6)).isoformat(),
            "isDaytime": now.hour < 12,
            "name": "Today",
            "shortForecast": "Sunny",
            "temperature": 70,
            "temperatureUnit": "F",
        }
        with open(self.dispatcher.settings.WEATHER_FORECAST_FILE, "w") as f:
            json.dump({"periods": [period]}, f)

        sent = []
        self.dispatcher.weather.broadcast_to_subscribers = lambda msg, key: sent.append((msg, key))
        self.dispatcher.weather.handle_daily_forecasts(now)

        key = f"forecast_{time_str}_sent_date"
        self.assertTrue(sent)
        self.assertEqual(self.dispatcher.core.dispatcher_state.get(key), str(now.date()))

    def test_run_periodic_task_rejects_invalid_interval(self):
        start = time.time()
        self.dispatcher.core.run_periodic_task(lambda now: None, 0, "invalid")
        self.assertLess(time.time() - start, 0.5)

    def test_temp_group_auto_create_and_tagsend_bypasses_node_tag_send(self):
        sender_id = "!temp1001"
        member_id = "!temp2002"

        self.dispatcher.core.subscribers = {
            sender_id: {"name": "Alpha", "node_tag_send": False},
            member_id: {"name": "Bravo", "node_tag_send": False},
        }

        resp_sender = self.dispatcher.commands._cmd_tagin(sender_id, "teamup")
        resp_member = self.dispatcher.commands._cmd_tagin(member_id, "TEAMUP")
        self.assertIn("temporary group TEAMUP", resp_sender)
        self.assertIn("temporary group TEAMUP", resp_member)

        sent = []
        self.dispatcher.commands.send_meshtastic_message = lambda text, **kwargs: sent.append((text, kwargs))

        send_resp = self.dispatcher.commands._cmd_tagsend(sender_id, "TEAMUP/On my way")
        self.assertIsNone(send_resp)
        dests = sorted(msg[1].get("destinationId") for msg in sent)
        self.assertEqual(dests, sorted([member_id, sender_id]))

        group = self.dispatcher.gb_db.get_temp_group("TEAMUP")
        self.assertIsNotNone(group)
        self.assertIn(sender_id, group["members"])
        self.assertIn(member_id, group["members"])

    def test_temp_group_expiry_cleanup_removes_stale_group(self):
        self.dispatcher.settings.TEMP_GROUP_TTL_DAYS = 1
        now_ts = int(time.time())
        stale_ts = now_ts - (3 * 86400)

        self.dispatcher.gb_db.upsert_temp_group(
            "STALEGRP",
            members=["!old0001"],
            created_at=stale_ts,
            last_activity=stale_ts,
        )
        self.assertIsNotNone(self.dispatcher.gb_db.get_temp_group("STALEGRP"))

        removed = self.dispatcher.commands.cleanup_expired_temp_groups()
        self.assertGreaterEqual(removed, 1)
        self.assertIsNone(self.dispatcher.gb_db.get_temp_group("STALEGRP"))

    def test_temp_group_admin_lock_and_open(self):
        admin_id = "!admin001"
        user_a = "!usera001"
        user_b = "!userb001"

        self.dispatcher.core.subscribers = {
            admin_id: {"name": "Admin", "tags": ["ADMIN"]},
            user_a: {"name": "Alice", "tags": []},
            user_b: {"name": "Bob", "tags": []},
        }

        self.dispatcher.commands._cmd_tagin(user_a, "opsroom")
        self.dispatcher.commands._cmd_tagin(user_b, "opsroom")

        denied = self.dispatcher.commands._cmd_tagshut(user_a, "opsroom")
        self.assertEqual(denied, "Access Denied.")

        locked_msg = self.dispatcher.commands._cmd_tagshut(admin_id, "opsroom")
        self.assertIn("now locked", locked_msg)
        group = self.dispatcher.gb_db.get_temp_group("OPSROOM")
        self.assertTrue(group["locked"])

        send_locked = self.dispatcher.commands._cmd_tagsend(user_a, "OPSROOM/Test while locked")
        self.assertIn("locked", send_locked.lower())

        reopened = self.dispatcher.commands._cmd_tagopen(admin_id, "opsroom")
        self.assertIn("now open", reopened)
        group = self.dispatcher.gb_db.get_temp_group("OPSROOM")
        self.assertFalse(group["locked"])

        sent = []
        self.dispatcher.commands.send_meshtastic_message = lambda text, **kwargs: sent.append((text, kwargs))
        send_ok = self.dispatcher.commands._cmd_tagsend(user_a, "OPSROOM/Test after open")
        self.assertIsNone(send_ok)
        self.assertEqual(len(sent), 2)

    def test_temp_group_tagkill_deletes_group_and_clears_active_channels(self):
        admin_id = "!admin002"
        user_a = "!usera002"
        user_b = "!userb002"
        self.dispatcher.core.subscribers = {
            admin_id: {"name": "Admin", "tags": ["ADMIN"]},
            user_a: {"name": "Alice", "tags": []},
            user_b: {"name": "Bob", "tags": []},
        }

        self.dispatcher.commands._cmd_tagin(user_a, "teamred")
        self.dispatcher.commands._cmd_tagin(user_b, "teamred")
        self.assertIsNotNone(self.dispatcher.gb_db.get_temp_group("TEAMRED"))
        self.assertEqual(self.dispatcher.gb_db.get_node_status(user_a).get("active_tag_channel"), "TEAMRED")
        self.assertEqual(self.dispatcher.gb_db.get_node_status(user_b).get("active_tag_channel"), "TEAMRED")

        kill_resp = self.dispatcher.commands._cmd_tagkill(admin_id, "teamred")
        self.assertIn("deleted", kill_resp.lower())
        self.assertIsNone(self.dispatcher.gb_db.get_temp_group("TEAMRED"))

        status_a = self.dispatcher.gb_db.get_node_status(user_a) or {}
        status_b = self.dispatcher.gb_db.get_node_status(user_b) or {}
        self.assertNotIn("active_tag_channel", status_a)
        self.assertNotIn("active_tag_channel", status_b)

    def test_process_queued_run_weather_fetcher_command(self):
        weather_script = os.path.join(self.dispatcher.settings.BASE_DIR, "weather_fetcher.py")
        with open(weather_script, "w", encoding="utf-8") as f:
            f.write("print('ok')\n")

        calls = []

        class DummyResult:
            returncode = 0
            stdout = "done"
            stderr = ""

        original_run = self.dispatcher.commands.subprocess.run

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return DummyResult()

        self.dispatcher.commands.subprocess.run = fake_run
        try:
            self.dispatcher.gb_db.enqueue_command_job(
                {"command": "run_weather_fetcher"},
                source_file="test:run_weather_fetcher",
            )
            self.dispatcher.commands.process_command_jobs(max_jobs=5)
        finally:
            self.dispatcher.commands.subprocess.run = original_run

        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0][1].endswith("weather_fetcher.py"))
        self.assertEqual(self.dispatcher.gb_db.count_command_dead_letters(), 0)

    def test_process_queued_maintenance_backup_and_restore(self):
        auto_dir = self.dispatcher.settings.AUTO_BACKUP_DIR
        source_path = os.path.join(auto_dir, "uploaded_restore_20260213_000001_abcd1234.db")
        with open(source_path, "wb") as f:
            f.write(b"sqlite-mock")

        backup_calls = []
        restore_calls = []
        original_create_backup = self.dispatcher.commands.gb_db.create_db_backup
        original_restore_backup = self.dispatcher.commands.gb_db.restore_database_from_backup

        def fake_create_db_backup(output_dir, filename_prefix="guardianbridge_db", now_ts=None, retries=5):
            backup_calls.append((output_dir, filename_prefix))
            return os.path.join(output_dir, f"{filename_prefix}_mock.db")

        def fake_restore_database(path, retries=5):
            restore_calls.append(path)
            return True

        self.dispatcher.commands.gb_db.create_db_backup = fake_create_db_backup
        self.dispatcher.commands.gb_db.restore_database_from_backup = fake_restore_database

        try:
            self.dispatcher.gb_db.enqueue_command_job(
                {"command": "maintenance_backup_db"},
                source_file="test:maintenance_backup_db",
            )
            self.dispatcher.gb_db.enqueue_command_job(
                {
                    "command": "maintenance_restore_db",
                    "source_db_path": source_path,
                    "cleanup_source": True,
                },
                source_file="test:maintenance_restore_db",
            )
            self.dispatcher.commands.process_command_jobs(max_jobs=10)
        finally:
            self.dispatcher.commands.gb_db.create_db_backup = original_create_backup
            self.dispatcher.commands.gb_db.restore_database_from_backup = original_restore_backup

        self.assertGreaterEqual(len(backup_calls), 2)  # one for backup, one safety backup during restore
        self.assertIn(source_path, restore_calls)
        self.assertFalse(os.path.exists(source_path))
        self.assertEqual(self.dispatcher.gb_db.count_command_dead_letters(), 0)

    def test_process_queued_maintenance_restore_rejects_outside_path(self):
        invalid_source = os.path.join(self.temp_dir.name, "outside_restore.db")
        with open(invalid_source, "wb") as f:
            f.write(b"sqlite-mock")

        self.dispatcher.gb_db.enqueue_command_job(
            {
                "command": "maintenance_restore_db",
                "source_db_path": invalid_source,
            },
            source_file="test:maintenance_restore_invalid",
        )
        self.dispatcher.commands.process_command_jobs(max_jobs=5)
        self.assertEqual(self.dispatcher.gb_db.count_command_dead_letters(), 1)

    def test_update_dispatcher_status_includes_alert_metrics(self):
        self.dispatcher.gb_db.enqueue_command_job(
            {"command": "broadcast", "text": "x"},
            source_file="test:queued_stale",
        )

        self.dispatcher.gb_db.add_command_dead_letter("cid1", "queued_stale.json", "test", {"x": 1})
        self.dispatcher.core.send_queue.put("m1")
        self.dispatcher.core.command_queue.put(("!a", "help"))
        self.dispatcher.core.iface = None
        self.dispatcher.core.record_runtime_error("test", "boom")
        future_now = int(time.time()) + 600
        original_core_time = self.dispatcher.core.time.time
        original_db_time = self.dispatcher.gb_db.time.time
        try:
            self.dispatcher.core.time.time = lambda: future_now
            self.dispatcher.gb_db.time.time = lambda: future_now
            self.dispatcher.core.update_dispatcher_status()
        finally:
            self.dispatcher.core.time.time = original_core_time
            self.dispatcher.gb_db.time.time = original_db_time

        payload = self.dispatcher.core.load_json(self.dispatcher.settings.DISPATCHER_STATUS_FILE)
        self.assertIsInstance(payload, dict)
        metrics = payload.get("metrics", {})
        self.assertGreaterEqual(metrics.get("command_backlog_count", 0), 1)
        self.assertGreaterEqual(metrics.get("command_dead_letter_count", 0), 1)
        self.assertGreaterEqual(metrics.get("send_queue_depth", 0), 1)
        self.assertGreaterEqual(metrics.get("command_queue_depth", 0), 1)
        alerts = payload.get("alerts", [])
        alert_codes = {a.get("code") for a in alerts if isinstance(a, dict)}
        self.assertIn("radio_disconnected", alert_codes)
        self.assertIn("command_dead_letters_present", alert_codes)
        self.assertIn("command_backlog_oldest_stale", alert_codes)


if __name__ == "__main__":
    unittest.main()
