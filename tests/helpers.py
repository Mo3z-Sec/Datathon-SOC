"""Shared helpers for the test-suite."""
import os
import tempfile
from datetime import date, datetime, timedelta, timezone

from soc.assets import load_assets
from soc.config import BASE_DIR, load_settings
from soc.service import SocService

ANALYST = "analyst-token-0123456789"
VIEWER = "viewer-token-0123456789abc"
DAY = date(2026, 10, 16)
ASSETS_PATH = BASE_DIR / "data" / "assets.csv"


def assets():
    return load_assets(ASSETS_PATH)


def make_settings(tmpdir, **extra):
    env = {"SOC_ANALYST_TOKEN": ANALYST, "SOC_VIEWER_TOKEN": VIEWER,
           "SOC_DB_PATH": os.path.join(tmpdir, "test.db")}
    env.update(extra)
    return load_settings(env)


def make_service(tmpdir, ai_post=None, **extra):
    return SocService(make_settings(tmpdir, **extra), ai_post=ai_post)


class TempDirMixin:
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()


_BASE = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
_counter = [0]


def mklog(offset_s, event_type, asset="VPN Gateway", hour=None, **kw):
    """Hand-built log line. `hour` overrides the UTC hour of the base time."""
    _counter[0] += 1
    base = _BASE if hour is None else _BASE.replace(hour=hour)
    log = {"log_id": f"T-{_counter[0]:06d}", "timestamp": (base + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "source": "auth", "asset": asset, "event_type": event_type, "username": None, "src_ip": None, "dst_ip": None,
           "dst_port": None, "outcome": None, "message": "", "details": {}, "simulated": True, "sim_scenario": None}
    log.update(kw)
    return log
