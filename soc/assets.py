"""Hospital asset inventory (simulated). Adapted from the team's shared/assets.csv:
the original columns (asset, criticality, simulated) are kept; extra columns add
type, department, subnet and clinical flags used for risk scoring."""
from __future__ import annotations

import csv
from dataclasses import dataclass, asdict
from pathlib import Path

TRUE = {"true", "1", "yes", "y"}


@dataclass(frozen=True)
class Asset:
    asset: str
    criticality: int
    asset_id: str = ""
    type: str = "server"
    department: str = ""
    subnet: str = ""
    patient_care: bool = False
    holds_phi: bool = False
    description: str = ""
    simulated: bool = True

    def to_dict(self):
        return asdict(self)


def load_assets(path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Asset inventory not found: {p}")
    out = {}
    with p.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            name = (row.get("asset") or "").strip()
            if not name:
                continue
            crit = int(row.get("criticality") or 1)
            if not 1 <= crit <= 5:
                raise ValueError(f"criticality for '{name}' must be 1..5")
            out[name] = Asset(
                asset=name,
                criticality=crit,
                asset_id=(row.get("asset_id") or "").strip(),
                type=(row.get("type") or "server").strip(),
                department=(row.get("department") or "").strip(),
                subnet=(row.get("subnet") or "").strip(),
                patient_care=(row.get("patient_care") or "").strip().lower() in TRUE,
                holds_phi=(row.get("holds_phi") or "").strip().lower() in TRUE,
                description=(row.get("description") or "").strip(),
            )
    if not out:
        raise ValueError("Asset inventory is empty")
    return out


def host_ip(asset: Asset, n: int) -> str:
    """A synthetic host address inside the asset's subnet (n = 0..200)."""
    prefix = asset.subnet.split("/")[0].rsplit(".", 1)[0] if asset.subnet else "10.0.0"
    return f"{prefix}.{10 + (n % 200)}"
