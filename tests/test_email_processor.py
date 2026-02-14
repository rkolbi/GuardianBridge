import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
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

    pytz = types.ModuleType("pytz")
    pytz.UTC = DummyTZ()
    pytz.timezone = lambda name: DummyTZ()
    _install_stub("pytz", pytz)

    class DummyAND:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class DummyMailBox:
        messages = []

        def __init__(self, *args, **kwargs):
            self.moved = []

        def login(self, *args, **kwargs):
            return self

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def fetch(self, *args, **kwargs):
            return list(self.messages)

        def move(self, uids, folder):
            self.moved.append((list(uids), folder))

    imap_tools = types.ModuleType("imap_tools")
    imap_tools.MailBox = DummyMailBox
    imap_tools.AND = DummyAND
    _install_stub("imap_tools", imap_tools)

    class DummySoup:
        def __init__(self, html, parser):
            self.html = html or ""

        def get_text(self, separator="\n"):
            return self.html

    bs4 = types.ModuleType("bs4")
    bs4.BeautifulSoup = DummySoup
    _install_stub("bs4", bs4)

    dateutil = types.ModuleType("dateutil")
    dateutil_tz = types.ModuleType("dateutil.tz")
    dateutil_tz.gettz = lambda *args, **kwargs: None
    _install_stub("dateutil", dateutil)
    _install_stub("dateutil.tz", dateutil_tz)


def _import_email_processor():
    _install_stubs()
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "email_processor.py"
    spec = importlib.util.spec_from_file_location("email_processor", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["email_processor"] = module
    spec.loader.exec_module(module)
    return module


class DummyMsg:
    def __init__(self, uid, from_addr, subject, text=None, html=None, headers=None):
        self.uid = uid
        self.from_ = from_addr
        self.subject = subject
        self.text = text
        self.html = html
        self.headers = headers or {}


class EmailProcessorTests(unittest.TestCase):
    def setUp(self):
        self.email_processor = _import_email_processor()
        self.temp_dir = tempfile.TemporaryDirectory()
        settings = self.email_processor.settings

        settings.DATA_DIR = self.temp_dir.name
        settings.OUTGOING_EMAIL_FILE = os.path.join(self.temp_dir.name, "outgoing_emails.json")
        settings.EMAIL_RATE_LIMIT_FILE = os.path.join(self.temp_dir.name, "email_rate_limit.json")
        settings.EMAIL_BLOCKLIST_FILE = os.path.join(self.temp_dir.name, "email_blocklist.json")
        settings.SOS_EMAIL_INSTRUCTIONS_FILE = os.path.join(self.temp_dir.name, "sos_instructions.txt")
        settings.DB_PATH = os.path.join(self.temp_dir.name, "guardianbridge.db")
        settings.TRASH_FOLDER_NAME = ""
        settings.EMAIL_RATE_LIMIT_MAX = 0
        settings.EMAIL_RATE_LIMIT_WINDOW_SECONDS = 0
        settings.MAX_EMAIL_BODY_LEN = 500

        self.email_processor.gb_db._initialized = False
        self.email_processor.gb_db.ensure_db()
        self.email_processor.gb_db.load_subscribers_dict = lambda: {}

        self.feedback = []
        self.email_processor.send_feedback_email = (
            lambda recipient, subject, body: self.feedback.append((recipient, subject, body))
        )
        self.email_processor.MailBox.messages = []

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_broadcast_email_creates_command_and_feedback(self):
        sender_email = "admin@example.com"
        self.email_processor.gb_db.load_subscribers_dict = lambda: {
            "!aaaa1111": {
                "email": sender_email,
                "name": "Admin",
                "emailbroadcast": True,
            }
        }
        msg = DummyMsg(1, sender_email, "broadcast", text="Hello world")
        self.email_processor.MailBox.messages = [msg]

        self.email_processor.process_incoming_emails()

        jobs = self.email_processor.gb_db.list_command_jobs(statuses=["queued"])
        self.assertEqual(len(jobs), 1)
        data = jobs[0]["payload"]
        self.assertEqual(data.get("command"), "broadcast")
        self.assertIn("FM Admin:", data.get("text", ""))
        self.assertIn("Hello world", data.get("text", ""))
        self.assertTrue(self.feedback)

    def test_tag_email_creates_relay_command(self):
        sender_email = "tagger@example.com"
        self.email_processor.gb_db.load_subscribers_dict = lambda: {
            "!sender": {
                "email": sender_email,
                "name": "Tagger",
                "emailbroadcast": True,
            },
            "!node1": {"tags": ["CERT"], "email_receive": True},
            "!node2": {"tags": ["MEDICAL"], "email_receive": False},
        }
        msg = DummyMsg(2, sender_email, "Tag CERT MEDICAL", text="Meet at HQ")
        self.email_processor.MailBox.messages = [msg]

        self.email_processor.process_incoming_emails()

        jobs = self.email_processor.gb_db.list_command_jobs(statuses=["queued"])
        self.assertEqual(len(jobs), 1)
        data = jobs[0]["payload"]
        self.assertEqual(data.get("command"), "relay")
        self.assertEqual(data.get("recipients"), ["!node1"])
        self.assertTrue(self.feedback)

    def test_find_recipients_in_subject_matches_name_and_id(self):
        subscribers = {
            "!abcd1234": {"name": "Alice"},
            "!deadbeef": {"name": "Bob"},
        }
        subject = "For !deadbeef and alice"
        recipients = self.email_processor.find_recipients_in_subject(subject, subscribers)
        self.assertEqual(set(recipients), {"!abcd1234", "!deadbeef"})

    def test_process_incoming_emails_uses_to_header_fallback(self):
        sender_email = "sender@example.com"
        target_node = "!a1b2c3d4"
        self.email_processor.gb_db.load_subscribers_dict = lambda: {
            target_node: {"email_receive": True, "name": "Target"},
        }
        msg = DummyMsg(
            4,
            sender_email,
            "Hello",
            text="Hi there",
            headers={"to": ["user@example.com", target_node]},
        )
        self.email_processor.MailBox.messages = [msg]

        self.email_processor.process_incoming_emails()

        jobs = self.email_processor.gb_db.list_command_jobs(statuses=["queued"])
        self.assertEqual(len(jobs), 1)
        data = jobs[0]["payload"]
        self.assertEqual(data.get("command"), "relay")
        self.assertEqual(data.get("recipients"), [target_node])

    def test_blocklisted_sender_is_ignored(self):
        sender_email = "blocked@example.com"
        with open(self.email_processor.settings.EMAIL_BLOCKLIST_FILE, "w") as f:
            json.dump([sender_email], f)
        self.email_processor.gb_db.load_subscribers_dict = lambda: {
            "!sender": {
                "email": sender_email,
                "name": "Blocked",
                "emailbroadcast": True,
            }
        }
        msg = DummyMsg(3, sender_email, "broadcast", text="Do not process")
        self.email_processor.MailBox.messages = [msg]

        self.email_processor.process_incoming_emails()

        self.assertEqual(self.email_processor.gb_db.list_command_jobs(statuses=["queued"]), [])
        self.assertEqual(self.feedback, [])

    def test_send_pending_outgoing_emails_sos_instructions(self):
        sent = []

        class DummySMTP:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def starttls(self):
                return None

            def login(self, user, password):
                return None

            def send_message(self, msg):
                sent.append(msg)

        self.email_processor.smtplib.SMTP = DummySMTP
        self.email_processor.gb_db.load_subscribers_dict = lambda: {}

        outgoing = [
            {
                "recipient": "alert@example.com",
                "subject": "SOS Alert",
                "body": "Emergency message",
                "sender_node": "GuardianBridge",
                "is_sos": True,
            }
        ]
        for msg in outgoing:
            self.email_processor.gb_db.add_outgoing_email(msg)
        with open(self.email_processor.settings.SOS_EMAIL_INSTRUCTIONS_FILE, "w") as f:
            f.write("Follow these steps.")

        self.email_processor.send_pending_outgoing_emails()

        self.assertEqual(len(sent), 1)
        payload = sent[0].get_payload()
        self.assertIn("Emergency message", payload)
        self.assertIn("Follow these steps.", payload)

        cleared = self.email_processor.gb_db.fetch_outgoing_emails()
        self.assertEqual(cleared, [])

    def test_send_pending_outgoing_emails_deletes_already_sent_rows_on_partial_failure(self):
        class DummySMTP:
            def __init__(self, *args, **kwargs):
                self.calls = 0

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def starttls(self):
                return None

            def login(self, user, password):
                return None

            def send_message(self, msg):
                self.calls += 1
                if self.calls >= 2:
                    raise RuntimeError("smtp send failed")

        self.email_processor.smtplib.SMTP = DummySMTP
        self.email_processor.gb_db.load_subscribers_dict = lambda: {}

        self.email_processor.gb_db.add_outgoing_email(
            {
                "recipient": "one@example.com",
                "subject": "First",
                "body": "Message one",
                "sender_node": "!node1",
            }
        )
        self.email_processor.gb_db.add_outgoing_email(
            {
                "recipient": "two@example.com",
                "subject": "Second",
                "body": "Message two",
                "sender_node": "!node2",
            }
        )

        self.email_processor.send_pending_outgoing_emails()

        remaining = self.email_processor.gb_db.fetch_outgoing_emails()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].get("subject"), "Second")


if __name__ == "__main__":
    unittest.main()
