"""Generate a realistic placeholder alert file so Felix's dashboard and Jason's
engine have a concrete target *today*, before the real models are wired in.

IMPORTANT: network_score / anomaly_score here are SIMULATED placeholders seeded by
the true label so the file looks plausible. They are NOT model predictions.
Replace them with Hanan's and Bardia's real outputs later — the column names stay the same.

Run:  python shared/make_sample_alerts.py
Out:  shared/sample_alerts.csv
"""
from __future__ import annotations

import csv
import hashlib
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from schema import ALERT_COLUMNS, compute_risk_score, recommended_action, validate_alert_row

ROOT = Path(__file__).resolve().parent.parent
OUTPUTS = ROOT / "data_pipeline" / "outputs"
ASSETS_CSV = ROOT / "shared" / "assets.csv"
OUT_CSV = ROOT / "shared" / "sample_alerts.csv"

N_ROWS = 24
RNG = random.Random(42)


def load_assets() -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    if ASSETS_CSV.exists():
        with open(ASSETS_CSV, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append((r["asset"], int(r["criticality"])))
    if not rows:
        rows = [("EHR Server", 5), ("Nurse Workstation", 3), ("Guest Wi-Fi", 1)]
    return rows


def load_events() -> list[dict]:
    """Prefer the real CICIDS test split (has asset + criticality + label_binary)."""
    p = OUTPUTS / "cicids_test.csv"
    if not p.exists():
        return []
    events: list[dict] = []
    with open(p, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= 4000:
                break
            events.append(
                {
                    "label_binary": int(float(row.get("label_binary", 0))),
                    "asset": row.get("asset") or "Nurse Workstation",
                    "criticality": int(float(row.get("criticality", 3))),
                }
            )
    RNG.shuffle(events)
    return events[:N_ROWS]


def load_hashed_ips(limit: int) -> list[str]:
    p = OUTPUTS / "privacy_preview.csv"
    if not p.exists():
        return []
    ips: list[str] = []
    with open(p, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            v = (r.get("Source IP hashed") or "").strip()
            if v:
                ips.append(v)
            if len(ips) >= limit:
                break
    return ips


def fallback_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:12]


def plausibility(label: int) -> float:
    """High score if it's really an attack, low if normal (placeholder only)."""
    if label == 1:
        return RNG.uniform(0.70, 0.99)
    return RNG.uniform(0.02, 0.35)


def main() -> None:
    assets = load_assets()
    events = load_events()
    hashed = load_hashed_ips(N_ROWS)

    if not events:
        # no pipeline outputs yet -> synthesize from the asset table
        events = [
            {
                "label_binary": RNG.choice([0, 0, 1]),
                "asset": a,
                "criticality": c,
            }
            for a, c in (RNG.choice(assets) for _ in range(N_ROWS))
        ]

    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=N_ROWS)
    rows: list[dict] = []
    for i, ev in enumerate(events):
        label = ev["label_binary"]
        net = round(plausibility(label), 3)
        anom = round(plausibility(label) * RNG.uniform(0.4, 0.9), 3)
        threat = 1 if (label == 1 and RNG.random() < 0.5) else 0
        risk = compute_risk_score(net, anom, threat, ev["criticality"])
        src = hashed[i % len(hashed)] if hashed else fallback_hash(f"flow-{i}")
        rows.append(
            {
                "timestamp": (start + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "asset": ev["asset"],
                "criticality": ev["criticality"],
                "src_ip_hashed": src,
                "network_score": net,
                "anomaly_score": anom,
                "threat_flag": threat,
                "risk_score": risk,
                "recommended_action": recommended_action(risk),
            }
        )

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=ALERT_COLUMNS)
        w.writeheader()
        w.writerows(rows)

    bad = [validate_alert_row(r) for r in rows]
    n_bad = sum(1 for b in bad if b)
    print(f"Wrote {len(rows)} sample alerts -> {OUT_CSV}")
    print(f"Contract violations: {n_bad}")
    for r in rows[:5]:
        print(r)


if __name__ == "__main__":
    main()
