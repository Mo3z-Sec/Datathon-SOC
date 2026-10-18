"""Command-line helpers:  python -m soc.cli <command>

  gen-token             print a strong random access token
  init-env              create .env from .env.example with fresh random tokens (never overwrites)
  check-config          validate .env and show the effective (non-secret) settings
  generate [--out F]    write simulated logs as JSON Lines (default data/sample_logs.jsonl)
  seed                  generate simulated logs, load them into the database and run detection
  load FILE             load a JSONL file of SIMULATED logs, then run detection
  detect                re-run detection over the logs already in the database
  stats                 print database counters
"""
import argparse
import json
import os
import secrets
import sys
from datetime import date
from pathlib import Path

from .assets import load_assets
from .config import BASE_DIR, ConfigError, load_env_file, load_settings
from .generator import generate, to_jsonl
from .service import SocService


def init_env():
    """Create .env from .env.example with strong random tokens. Refuses to overwrite an existing file."""
    target, template = BASE_DIR / ".env", BASE_DIR / ".env.example"
    if target.exists():
        print(f"{target} already exists - leaving it untouched.")
        return 0
    text = template.read_text(encoding="utf-8")
    text = text.replace("SOC_ANALYST_TOKEN=CHANGE_ME_run_scripts_setup_sh", "SOC_ANALYST_TOKEN=" + secrets.token_urlsafe(32))
    text = text.replace("SOC_VIEWER_TOKEN=", "SOC_VIEWER_TOKEN=" + secrets.token_urlsafe(32), 1)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Created {target} (permissions 600) with new random tokens.")
    return 0


def generate_file(a):
    env = {**load_env_file(os.environ.get("SOC_ENV_FILE", BASE_DIR / ".env")), **os.environ}
    assets_path = Path(env.get("SOC_ASSETS_PATH") or BASE_DIR / "data" / "assets.csv")
    if not assets_path.is_absolute():
        assets_path = BASE_DIR / assets_path
    offset = float(env.get("SOC_UTC_OFFSET_HOURS", "0") or 0)
    day = date.fromisoformat(a.day) if a.day else None
    logs = generate(load_assets(assets_path), seed=a.seed, day=day, benign=a.benign, utc_offset_hours=offset)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(to_jsonl(logs))
    print(f"Wrote {len(logs)} SIMULATED logs to {a.out}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m soc.cli", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-token")
    sub.add_parser("init-env")
    sub.add_parser("check-config")
    g = sub.add_parser("generate")
    g.add_argument("--out", default=str(BASE_DIR / "data" / "sample_logs.jsonl"))
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--benign", type=int, default=300)
    g.add_argument("--day", help="YYYY-MM-DD (default: yesterday, UTC)")
    s = sub.add_parser("seed")
    s.add_argument("--seed", type=int, default=None)
    s.add_argument("--benign", type=int, default=300)
    s.add_argument("--keep", action="store_true", help="do not wipe existing data first")
    ld = sub.add_parser("load")
    ld.add_argument("file")
    sub.add_parser("detect")
    sub.add_parser("stats")
    a = ap.parse_args(argv)

    if a.cmd == "gen-token":
        print(secrets.token_urlsafe(32))
        return 0
    if a.cmd == "init-env":
        return init_env()
    if a.cmd == "generate":  # needs no token
        return generate_file(a)
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    if a.cmd == "check-config":
        print(json.dumps({"db_path": str(settings.db_path), "host": settings.host, "port": settings.port,
                          "ai_enabled": settings.ai_enabled, "viewer_token_set": bool(settings.viewer_token),
                          "utc_offset_hours": settings.utc_offset_hours}, indent=2))
        return 0
    svc = SocService(settings)
    if a.cmd == "seed":
        print(json.dumps(svc.simulate(seed=a.seed, benign=a.benign, replace=not a.keep, actor="cli"), indent=2))
    elif a.cmd == "load":
        with open(a.file, encoding="utf-8") as f:
            logs = [json.loads(line) for line in f if line.strip()]
        print(json.dumps(svc.ingest(logs)))
        print(json.dumps(svc.run_detection("cli")))
    elif a.cmd == "detect":
        print(json.dumps(svc.run_detection("cli")))
    elif a.cmd == "stats":
        st = svc.stats()
        print(json.dumps({k: st[k] for k in ("logs_total", "alerts_total", "open_alerts", "critical_open")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
