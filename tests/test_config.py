import os
import tempfile
import unittest

from soc.config import ConfigError, load_env_file, load_settings

TOKEN = "x" * 24


class ConfigTests(unittest.TestCase):
    def test_requires_a_strong_analyst_token(self):
        for env in ({}, {"SOC_ANALYST_TOKEN": ""}, {"SOC_ANALYST_TOKEN": "short"}, {"SOC_ANALYST_TOKEN": "CHANGE_ME_run_scripts_setup_sh"}):
            with self.assertRaises(ConfigError, msg=str(env)):
                load_settings(env)

    def test_viewer_token_rules(self):
        load_settings({"SOC_ANALYST_TOKEN": TOKEN, "SOC_VIEWER_TOKEN": ""})  # optional
        with self.assertRaises(ConfigError):
            load_settings({"SOC_ANALYST_TOKEN": TOKEN, "SOC_VIEWER_TOKEN": TOKEN})
        with self.assertRaises(ConfigError):
            load_settings({"SOC_ANALYST_TOKEN": TOKEN, "SOC_VIEWER_TOKEN": "tiny"})

    def test_secure_defaults(self):
        s = load_settings({"SOC_ANALYST_TOKEN": TOKEN})
        self.assertEqual((s.host, s.port, s.ai_provider, s.ai_enabled), ("127.0.0.1", 8000, "none", False))

    def test_validation_of_other_settings(self):
        base = {"SOC_ANALYST_TOKEN": TOKEN}
        for extra in ({"SOC_PORT": "0"}, {"SOC_PORT": "abc"}, {"SOC_UTC_OFFSET_HOURS": "99"}, {"SOC_AI_PROVIDER": "openai"}, {"SOC_AI_TIMEOUT": "x"}):
            with self.assertRaises(ConfigError, msg=str(extra)):
                load_settings({**base, **extra})

    def test_ai_needs_provider_and_key(self):
        base = {"SOC_ANALYST_TOKEN": TOKEN}
        self.assertFalse(load_settings({**base, "SOC_AI_PROVIDER": "anthropic"}).ai_enabled)
        self.assertFalse(load_settings({**base, "SOC_AI_API_KEY": "k"}).ai_enabled)
        self.assertTrue(load_settings({**base, "SOC_AI_PROVIDER": "anthropic", "SOC_AI_API_KEY": "k"}).ai_enabled)
        self.assertTrue(load_settings({**base, "SOC_AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "k"}).ai_enabled)

    def test_env_file_parsing_and_precedence(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".env")
            with open(p, "w") as f:
                f.write("# comment\n\nSOC_ANALYST_TOKEN='quoted-token-0123456789'\nSOC_PORT=9001\nBROKEN LINE\n")
            self.assertEqual(load_env_file(p), {"SOC_ANALYST_TOKEN": "quoted-token-0123456789", "SOC_PORT": "9001"})
            self.assertEqual(load_env_file(os.path.join(d, "missing")), {})
            old = dict(os.environ)
            try:
                os.environ.pop("SOC_ANALYST_TOKEN", None)
                os.environ["SOC_PORT"] = "9100"   # real environment wins over the file
                s = load_settings(env_file=p)
                self.assertEqual((s.analyst_token, s.port), ("quoted-token-0123456789", 9100))
            finally:
                os.environ.clear(); os.environ.update(old)


if __name__ == "__main__":
    unittest.main()
