import importlib
import json
import os
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from queue import Queue
from datetime import timedelta, tzinfo


def _install_stub(module_name, module_obj):
    sys.modules[module_name] = module_obj


def _install_stubs():
    dotenv = types.ModuleType("dotenv")
    dotenv.load_dotenv = lambda *args, **kwargs: None
    _install_stub("dotenv", dotenv)

    tzlocal = types.ModuleType("tzlocal")
    tzlocal.get_localzone_name = lambda: "UTC"
    _install_stub("tzlocal", tzlocal)

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

    meshtastic = types.ModuleType("meshtastic")
    class DummyMeshtasticException(Exception):
        pass
    meshtastic.MeshtasticException = DummyMeshtasticException
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

    pubsub = types.ModuleType("pubsub")
    class DummyPub:
        def subscribe(self, *args, **kwargs):
            return None
    pubsub.pub = DummyPub()
    _install_stub("pubsub", pubsub)


def _import_messaging():
    _install_stubs()
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    return importlib.import_module("dispatcher.messaging")


class MessagingQueueTests(unittest.TestCase):
    def setUp(self):
        self.messaging = _import_messaging()
        self.core = self.messaging.core
        import settings as settings_mod
        self.settings = settings_mod
        self.temp_dir = tempfile.TemporaryDirectory()

        self.settings.DATA_DIR = self.temp_dir.name
        self.settings.FAILED_DM_QUEUE_FILE = os.path.join(self.temp_dir.name, "failed_dm_queue.json")
        self.settings.OUTGOING_EMAIL_FILE = os.path.join(self.temp_dir.name, "outgoing_emails.json")
        self.settings.DB_PATH = os.path.join(self.temp_dir.name, "guardianbridge.db")

        self.messaging.gb_db._initialized = False
        self.messaging.gb_db.ensure_db()

        self.core.MIN_SEND_INTERVAL_SECONDS = 0
        self.core.log_channel_message = lambda *args, **kwargs: None
        self.core.send_queue = Queue()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_retry_queued_messages_for_node_filters_and_sends(self):
        queue = [
            {"destination_id": "!node1", "text": "one", "timestamp": "t1"},
            {"destination_id": "!node2", "text": "two", "timestamp": "t2"},
            {"destination_id": "!node1", "text": "three", "timestamp": "t3"},
        ]
        for msg in queue:
            self.messaging.gb_db.add_failed_dm(msg)

        sent = []
        self.messaging.send_meshtastic_message = lambda text, **kwargs: sent.append((text, kwargs))

        self.messaging.retry_queued_messages_for_node("!node1")

        self.assertEqual([item[0] for item in sent], ["one", "three"])
        remaining = self.messaging.gb_db.fetch_failed_dm_queue()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["destination_id"], "!node2")

    def test_sender_thread_worker_queues_failed_dm_on_exception(self):
        messaging = self.messaging

        class DummyIface:
            def sendText(self, **kwargs):
                raise messaging.meshtastic.MeshtasticException("fail")

        self.core.iface = DummyIface()

        worker = threading.Thread(target=self.messaging.sender_thread_worker)
        worker.start()

        self.core.send_queue.put({"text": "Hello", "destinationId": "!node1", "wantAck": True})
        self.core.send_queue.put(None)
        worker.join(timeout=2)

        queued = self.messaging.gb_db.fetch_failed_dm_queue()
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["destination_id"], "!node1")
        self.assertEqual(queued[0]["text"], "Hello")


if __name__ == "__main__":
    unittest.main()
