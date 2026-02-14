import json
import os
import sys
import tempfile
import threading
import types
import unittest
from datetime import datetime, timezone


def _install_stub(module_name, module_obj):
    sys.modules[module_name] = module_obj


def _install_stubs():
    dotenv = types.ModuleType("dotenv")
    dotenv.load_dotenv = lambda *args, **kwargs: None
    _install_stub("dotenv", dotenv)


_install_stubs()

import settings
import gb_db


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        settings.DATA_DIR = self.temp_dir.name
        settings.DB_PATH = os.path.join(self.temp_dir.name, "guardianbridge.db")
        settings.SUBSCRIBERS_FILE = os.path.join(self.temp_dir.name, "subscribers.json")
        settings.NODE_STATUS_FILE = os.path.join(self.temp_dir.name, "node_status.json")
        settings.SOS_LOG_FILE = os.path.join(self.temp_dir.name, "sos_log.json")

        gb_db._initialized = False
        if os.path.exists(settings.DB_PATH):
            os.remove(settings.DB_PATH)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ensure_db_threadsafe(self):
        errors = []

        def worker():
            try:
                gb_db.ensure_db()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertTrue(os.path.exists(settings.DB_PATH))

    def test_concurrent_chat_log_reads_and_writes(self):
        gb_db.ensure_db()
        errors = []

        def writer():
            for i in range(20):
                try:
                    gb_db.append_chat_log(
                        {
                            "from": "!node",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "text": f"msg {i}",
                        },
                        max_entries=0,
                    )
                except Exception as exc:
                    errors.append(exc)

        def reader():
            for _ in range(20):
                try:
                    gb_db.get_chat_logs(limit=50)
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        messages, _ = gb_db.get_chat_logs(limit=200)
        self.assertGreaterEqual(len(messages), 20)


if __name__ == "__main__":
    unittest.main()
