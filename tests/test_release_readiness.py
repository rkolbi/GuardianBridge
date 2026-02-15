import re
import unittest
from pathlib import Path


class ReleaseReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.map_php = (cls.repo_root / "www" / "map.php").read_text(encoding="utf-8")
        cls.mop_php = (cls.repo_root / "www" / "mop.php").read_text(encoding="utf-8")
        cls.nodes_api_php = (cls.repo_root / "www" / "map-items" / "api_get_nodes.php").read_text(encoding="utf-8")
        cls.preflight_py = (cls.repo_root / "scripts" / "pre_release_preflight.py").read_text(encoding="utf-8")
        cls.healthcheck_py = (cls.repo_root / "scripts" / "healthcheck_guardianbridge.py").read_text(encoding="utf-8")

    def test_nodes_api_supports_include_all_mode(self):
        self.assertIn("$include_all = false;", self.nodes_api_php)
        self.assertIn("isset($_GET['include_all'])", self.nodes_api_php)
        self.assertIn("$cache_variant = $include_all ? 'all' : 'live';", self.nodes_api_php)
        self.assertIn("api_nodes_cache_' . $cache_variant . '.json'", self.nodes_api_php)
        self.assertIn("if ($include_all && is_array($subscribers))", self.nodes_api_php)
        self.assertIn("'sos_role' => 'NONE'", self.nodes_api_php)

    def test_map_and_mop_have_live_all_toggle_ui_and_api_switch(self):
        for page in (self.map_php, self.mop_php):
            self.assertIn("id=\"node-scope-toggle\"", page)
            self.assertIn("id=\"node-list-title\"", page)
            self.assertIn("const NODE_SCOPE_LIVE = 'live';", page)
            self.assertIn("const NODE_SCOPE_ALL = 'all';", page)
            self.assertIn("function getNodesApiUrl()", page)
            self.assertIn("/map-items/api_get_nodes.php?include_all=1", page)

    def test_healthcheck_and_preflight_use_same_dispatcher_age_default(self):
        preflight_match = re.search(
            r"max-dispatcher-age-seconds[\"']\s*,\s*type=int,\s*default=(\d+)",
            self.preflight_py,
        )
        healthcheck_match = re.search(
            r"max-age-seconds[\"']\s*,\s*type=int,\s*default=(\d+)",
            self.healthcheck_py,
        )
        self.assertIsNotNone(preflight_match)
        self.assertIsNotNone(healthcheck_match)
        self.assertEqual(preflight_match.group(1), healthcheck_match.group(1))
        self.assertEqual(preflight_match.group(1), "120")


if __name__ == "__main__":
    unittest.main()
