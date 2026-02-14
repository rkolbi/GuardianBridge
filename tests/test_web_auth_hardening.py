import unittest
from pathlib import Path


class WebAuthHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.map_php = (cls.repo_root / "www" / "map.php").read_text(encoding="utf-8")
        cls.mop_php = (cls.repo_root / "www" / "mop.php").read_text(encoding="utf-8")
        cls.db_php = (cls.repo_root / "www" / "db.php").read_text(encoding="utf-8")
        cls.dashboard_api_php = (cls.repo_root / "www" / "map-items" / "api_get_dashboard.php").read_text(encoding="utf-8")
        cls.nodes_api_php = (cls.repo_root / "www" / "map-items" / "api_get_nodes.php").read_text(encoding="utf-8")

    def test_map_and_mop_use_distinct_session_keys(self):
        self.assertIn("$_SESSION['map_loggedin']", self.map_php)
        self.assertNotIn("$_SESSION['loggedin']", self.map_php)

        self.assertIn("$_SESSION['mop_loggedin']", self.mop_php)
        self.assertNotIn("$_SESSION['loggedin']", self.mop_php)

    def test_shared_map_items_apis_accept_map_or_mop_session(self):
        api_files = [
            "api_get_nodes.php",
            "api_get_dashboard.php",
            "api_get_chat.php",
            "api_get_chat_stream.php",
            "api_get_pins.php",
            "api_manage_blocklist.php",
            "api_download_sos_log.php",
        ]
        for filename in api_files:
            text = (self.repo_root / "www" / "map-items" / filename).read_text(encoding="utf-8")
            self.assertIn("$_SESSION['map_loggedin']", text, msg=filename)
            self.assertIn("$_SESSION['mop_loggedin']", text, msg=filename)
            self.assertNotIn("$_SESSION['loggedin']", text, msg=filename)

    def test_map_admin_hash_has_no_default_fallback(self):
        self.assertIn("ADMIN_PASSWORD_HASH", self.map_php)
        self.assertNotIn("default_admin_password_hash", self.map_php)
        self.assertIn("Admin login disabled", self.map_php)

    def test_db_has_persistent_login_failure_tracking(self):
        self.assertIn("CREATE TABLE IF NOT EXISTS login_failures", self.db_php)
        self.assertIn("function gb_record_login_failure", self.db_php)
        self.assertIn("function gb_get_recent_login_failure_stats", self.db_php)
        self.assertIn("function gb_clear_login_failures", self.db_php)
        self.assertIn("function gb_prune_login_failures", self.db_php)

    def test_requirements_are_version_pinned(self):
        requirements = (self.repo_root / "requirements.txt").read_text(encoding="utf-8").splitlines()
        active = [line.strip() for line in requirements if line.strip() and not line.strip().startswith("#")]
        self.assertGreater(len(active), 0)
        for line in active:
            self.assertIn("==", line, msg=f"Unpinned requirement: {line}")
            name, version = line.split("==", 1)
            self.assertTrue(name.strip(), msg=f"Missing package name: {line}")
            self.assertTrue(version.strip(), msg=f"Missing package version: {line}")

    def test_web_actions_use_queued_commands_not_shell_exec(self):
        self.assertNotIn("shell_exec('python3", self.map_php)
        self.assertNotIn("shell_exec('python3", self.mop_php)
        self.assertNotIn("sudo systemctl stop guardianbridge.service", self.map_php)
        self.assertNotIn("sudo systemctl start guardianbridge.service", self.map_php)
        self.assertIn("gb_enqueue_command_job", self.map_php)
        self.assertIn("gb_enqueue_command_job", self.mop_php)
        self.assertIn("'command' => 'run_weather_fetcher'", self.map_php)
        self.assertIn("'command' => 'run_email_processor'", self.map_php)
        self.assertIn("'command' => 'maintenance_backup_db'", self.map_php)
        self.assertIn("'command' => 'maintenance_restore_db'", self.map_php)
        self.assertIn("'command' => 'maintenance_vacuum_db'", self.map_php)
        self.assertIn("'command' => 'run_weather_fetcher'", self.mop_php)
        self.assertIn("'command' => 'run_email_processor'", self.mop_php)

    def test_db_has_command_job_queue_table_and_helper(self):
        self.assertIn("CREATE TABLE IF NOT EXISTS command_jobs", self.db_php)
        self.assertIn("function gb_enqueue_command_job", self.db_php)

    def test_dashboard_api_avoids_shell_process_calls(self):
        self.assertNotIn("shell_exec(", self.dashboard_api_php)
        self.assertNotIn("systemctl", self.dashboard_api_php)
        self.assertNotIn("journalctl", self.dashboard_api_php)

    def test_ops_notes_field_available_in_map_mop_and_nodes_api(self):
        self.assertIn("name=\"ops_notes\"", self.map_php)
        self.assertIn("name=\"ops_notes\"", self.mop_php)
        self.assertIn("userData.ops_notes", self.map_php)
        self.assertIn("userData.ops_notes", self.mop_php)
        self.assertIn("'ops_notes' => $user_data['ops_notes'] ?? null", self.nodes_api_php)


if __name__ == "__main__":
    unittest.main()
