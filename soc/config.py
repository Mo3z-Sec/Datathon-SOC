"""Settings loaded from environment variables (and an optional .env file).

Secure by default: the app refuses to start without a strong analyst token,
binds to localhost unless told otherwise, and keeps the external AI API off.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MIN_TOKEN_LEN = 16


class ConfigError(Exception):
    """Raised when the configuration is missing or unsafe."""


def load_env_file(path):
    """Parse a simple KEY=VALUE file. Ignores blanks and # comments."""
    values = {}
    p = Path(path)
    if not p.is_file():
        return values
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        values[key.strip()] = val
    return values


@dataclass(frozen=True)
class Settings:
    db_path: Path
    assets_path: Path
    analyst_token: str
    viewer_token: str = ""
    host: str = "127.0.0.1"
    port: int = 8000
    ai_provider: str = "none"
    ai_api_key: str = ""
    ai_model: str = "claude-sonnet-5-5"
    ai_timeout: float = 20.0
    utc_offset_hours: float = 0.0
    max_page_size: int = 500

    @property
    def ai_enabled(self) -> bool:
        return self.ai_provider == "anthropic" and bool(self.ai_api_key)


def _check_token(name, value, required):
    if not value:
        if required:
            raise ConfigError(
                f"{name} is not set. Run scripts/setup.sh (it generates one) or set it in .env "
                f"(at least {MIN_TOKEN_LEN} characters)."
            )
        return
    if value.upper().startswith("CHANGE") or len(value) < MIN_TOKEN_LEN:
        raise ConfigError(
            f"{name} is a placeholder or too short (minimum {MIN_TOKEN_LEN} characters). "
            "Generate a strong one with: python -m soc.cli gen-token"
        )


def load_settings(environ=None, env_file=None) -> Settings:
    """Build Settings. Pass `environ` (a dict) in tests to avoid touching os.environ."""
    if environ is None:
        file_vals = load_env_file(env_file or os.environ.get("SOC_ENV_FILE", BASE_DIR / ".env"))
        environ = {**file_vals, **os.environ}  # real environment wins over the file

    def get(key, default=""):
        return environ.get(key, default)

    analyst = get("SOC_ANALYST_TOKEN")
    viewer = get("SOC_VIEWER_TOKEN")
    _check_token("SOC_ANALYST_TOKEN", analyst, required=True)
    _check_token("SOC_VIEWER_TOKEN", viewer, required=False)
    if viewer and viewer == analyst:
        raise ConfigError("SOC_VIEWER_TOKEN must differ from SOC_ANALYST_TOKEN.")

    provider = get("SOC_AI_PROVIDER", "none").strip().lower() or "none"
    if provider not in ("none", "anthropic"):
        raise ConfigError("SOC_AI_PROVIDER must be 'none' or 'anthropic'.")

    try:
        port = int(get("SOC_PORT", "8000"))
        offset = float(get("SOC_UTC_OFFSET_HOURS", "0"))
        timeout = float(get("SOC_AI_TIMEOUT", "20"))
    except ValueError as exc:
        raise ConfigError(f"Invalid numeric setting: {exc}") from exc
    if not (1 <= port <= 65535):
        raise ConfigError("SOC_PORT must be between 1 and 65535.")
    if not (-12 <= offset <= 14):
        raise ConfigError("SOC_UTC_OFFSET_HOURS must be between -12 and 14.")

    def path(key, default):
        p = Path(get(key, "") or default)
        return p if p.is_absolute() else BASE_DIR / p

    return Settings(
        db_path=path("SOC_DB_PATH", "data/soc.db"),
        assets_path=path("SOC_ASSETS_PATH", "data/assets.csv"),
        analyst_token=analyst,
        viewer_token=viewer,
        host=get("SOC_HOST", "127.0.0.1") or "127.0.0.1",
        port=port,
        ai_provider=provider,
        ai_api_key=get("SOC_AI_API_KEY") or get("ANTHROPIC_API_KEY"),
        ai_model=get("SOC_AI_MODEL", "claude-sonnet-5-5") or "claude-sonnet-5-5",
        ai_timeout=timeout,
        utc_offset_hours=offset,
    )
