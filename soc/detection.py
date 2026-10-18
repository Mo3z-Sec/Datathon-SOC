"""Deterministic detection rules.

Pure functions over a list of log dicts -> list of Finding. No machine learning and no
randomness: the same logs always yield the same findings. Thresholds live in
DetectionConfig so they can be tuned and unit-tested.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone

CATEGORIES = {
    "ransomware": "Ransomware",
    "ehr_access": "Suspicious EHR access",
    "brute_force": "Brute force",
    "malware": "Malware",
    "privilege_abuse": "Privilege abuse",
    "device_anomaly": "Medical device anomaly",
}

# severity = how bad this behaviour is on its own; impact tags feed the hospital-impact score.
RULES = {
    "BF-001": dict(category="brute_force", severity="medium", impact=["access"], mitre="T1110.001",
                   title="Repeated failed logins (brute force)"),
    "BF-002": dict(category="brute_force", severity="high", impact=["access"], mitre="T1110.003",
                   title="Password spraying across many accounts"),
    "BF-003": dict(category="brute_force", severity="high", impact=["access", "integrity"], mitre="T1078",
                   title="Successful login after repeated failures"),
    "EHR-001": dict(category="ehr_access", severity="high", impact=["phi"], mitre="T1213",
                    title="Bulk patient-record access without care relationship"),
    "EHR-002": dict(category="ehr_access", severity="medium", impact=["phi"], mitre="T1213",
                    title="After-hours record access without care relationship"),
    "EHR-003": dict(category="ehr_access", severity="high", impact=["phi"], mitre="T1213",
                    title="VIP patient record opened without care relationship"),
    "MAL-001": dict(category="malware", severity="high", impact=["integrity", "downtime"], mitre="T1204",
                    title="Antivirus detection that was not contained"),
    "MAL-002": dict(category="malware", severity="high", impact=["integrity"], mitre="T1059.001",
                    title="Encoded PowerShell launched by an application"),
    "MAL-003": dict(category="malware", severity="high", impact=["integrity"], mitre="T1071",
                    title="Connection to a known-bad address (possible C2)"),
    "RAN-001": dict(category="ransomware", severity="critical", impact=["patient_safety", "downtime"],
                    mitre="T1486", title="Mass file encryption activity"),
    "RAN-002": dict(category="ransomware", severity="high", impact=["downtime", "integrity"], mitre="T1490",
                    title="Backups or shadow copies tampered with"),
    "RAN-003": dict(category="ransomware", severity="critical", impact=["downtime"], mitre="T1486",
                    title="Ransom note created"),
    "PRIV-001": dict(category="privilege_abuse", severity="high", impact=["integrity"], mitre="T1098",
                     title="Suspicious addition to a privileged group"),
    "PRIV-002": dict(category="privilege_abuse", severity="medium", impact=["access"], mitre="T1078",
                     title="Service account used for interactive logon"),
    "PRIV-003": dict(category="privilege_abuse", severity="high", impact=["integrity"], mitre="T1070.001",
                     title="Security audit log cleared"),
    "DEV-001": dict(category="device_anomaly", severity="high", impact=["patient_safety"], mitre="T1071",
                    title="Medical device communicating with the internet"),
    "DEV-002": dict(category="device_anomaly", severity="high", impact=["patient_safety"], mitre="T1021",
                    title="Unapproved remote-admin connection to a medical device"),
    "DEV-003": dict(category="device_anomaly", severity="high", impact=["patient_safety"], mitre="T1046",
                    title="Port scanning involving a medical device"),
    "DEV-004": dict(category="device_anomaly", severity="medium", impact=["patient_safety"], mitre="T0857",
                    title="Device firmware changed outside a maintenance window"),
}


@dataclass
class DetectionConfig:
    bf_fail_threshold: int = 8
    bf_window: int = 300
    spray_users: int = 6
    spray_window: int = 600
    bf_success_fails: int = 5
    bf_success_window: int = 600
    ehr_bulk_patients: int = 20
    ehr_bulk_window: int = 600
    ehr_after_hours_min: int = 3
    ehr_after_hours_window: int = 3600
    business_start: int = 7
    business_end: int = 19
    utc_offset_hours: float = 0.0
    av_outbreak_count: int = 3
    av_outbreak_window: int = 3600
    ransom_files: int = 200
    ransom_gap: int = 300
    ransom_exts: tuple = (".locked", ".encrypted", ".crypt", ".enc", ".sim-locked")
    admin_groups: tuple = ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    approved_admins: tuple = ("sim.admin01", "sim.admin02")
    device_admin_ports: tuple = (22, 23, 3389, 445, 5900)
    device_admin_allowlist: tuple = ("10.50.0.5",)
    device_scan_ports: int = 15
    device_scan_window: int = 120
    office_parents: tuple = ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrord32.exe")
    backup_services: tuple = ("BackupAgent", "VeeamBackupSvc", "SQLWriter", "VSS")
    # Simulated indicators only (reserved documentation ranges / .invalid domains).
    ioc_ips: tuple = ("198.51.100.77", "198.51.100.200")
    ioc_domains: tuple = ("update-check.invalid",)


@dataclass
class Finding:
    rule_id: str
    asset: str
    first_ts: float
    last_ts: float
    events: list
    evidence: list
    confidence: float
    username: str = None
    src_ip: str = None
    severity: str = None
    facts: dict = field(default_factory=dict)

    @property
    def meta(self):
        return RULES[self.rule_id]

    @property
    def category(self):
        return self.meta["category"]

    @property
    def title(self):
        return self.meta["title"]

    @property
    def effective_severity(self):
        return self.severity or self.meta["severity"]

    @property
    def log_ids(self):
        return [e["log_id"] for e in self.events]


# ----------------------------------------------------------------------------- helpers
def parse_ts(value: str) -> float:
    d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_dur(sec: float) -> str:
    sec = int(round(sec))
    if sec < 60:
        return f"{sec}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def ratio_conf(value, threshold, lo=0.55, hi=0.95):
    """Confidence grows from `lo` at the threshold to `hi` at twice the threshold."""
    if threshold <= 0:
        return hi
    frac = max(0.0, min(1.0, (value - threshold) / threshold))
    return round(lo + (hi - lo) * frac, 3)


_INTERNAL = [ipaddress.ip_network(n) for n in
             ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]


def is_internal(ip) -> bool:
    """RFC1918/loopback/link-local. Documentation ranges (198.51.100.0/24 ...) count as EXTERNAL."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in n for n in _INTERNAL)


def _group(events, keyfn):
    out = {}
    for e in events:
        out.setdefault(keyfn(e), []).append(e)
    return out


def burst_clusters(events, window_s, min_count, distinct=None):
    """Clusters of time-ordered events where >= min_count events (or distinct values of
    distinct(e)) fall inside any `window_s` sliding window. Overlapping windows merge."""
    evs = sorted(events, key=lambda e: e["_ts"])
    out, left, cur, cur_end = [], 0, None, -1
    for right in range(len(evs)):
        while evs[right]["_ts"] - evs[left]["_ts"] > window_s:
            left += 1
        window = evs[left:right + 1]
        metric = len({distinct(e) for e in window}) if distinct else len(window)
        if metric >= min_count:
            if cur is not None and left <= cur_end:
                cur.extend(evs[cur_end + 1:right + 1])
            else:
                cur = list(window)
                out.append(cur)
            cur_end = right
    return out


def chain_clusters(events, gap_s):
    """Group time-ordered events into clusters separated by gaps longer than gap_s."""
    evs = sorted(events, key=lambda e: e["_ts"])
    out = []
    for e in evs:
        if out and e["_ts"] - out[-1][-1]["_ts"] <= gap_s:
            out[-1].append(e)
        else:
            out.append([e])
    return out


def _det(e):
    return e.get("details") or {}


def _mk(rule_id, cluster, asset, confidence, evidence, username=None, src_ip=None, severity=None, facts=None):
    ts = [e["_ts"] for e in cluster]
    return Finding(rule_id=rule_id, asset=asset, first_ts=min(ts), last_ts=max(ts), events=cluster,
                   evidence=evidence, confidence=round(min(0.99, max(0.05, confidence)), 3),
                   username=username, src_ip=src_ip, severity=severity, facts=facts or {})


def local_hour(ts, offset_hours):
    return int(((ts + offset_hours * 3600) % 86400) // 3600)


def after_hours(ts, cfg):
    h = local_hour(ts, cfg.utc_offset_hours)
    return h < cfg.business_start or h >= cfg.business_end


def _span(cluster):
    return cluster[-1]["_ts"] - cluster[0]["_ts"]


# ----------------------------------------------------------------------------- brute force
def rule_bf001(logs, assets, cfg):
    fails = [e for e in logs if e["event_type"] == "login_failure" and e.get("src_ip")]
    out = []
    for (ip, asset), evs in _group(fails, lambda e: (e["src_ip"], e["asset"])).items():
        for cl in burst_clusters(evs, cfg.bf_window, cfg.bf_fail_threshold):
            users = sorted({e["username"] for e in cl if e.get("username")})
            out.append(_mk("BF-001", cl, asset, ratio_conf(len(cl), cfg.bf_fail_threshold),
                           [f"{len(cl)} failed logins from {ip} against {asset} within {fmt_dur(_span(cl))}",
                            f"Targeted account(s): {', '.join(users[:5]) or 'unknown'}"],
                           username=users[0] if len(users) == 1 else None, src_ip=ip,
                           facts={"count": len(cl), "duration": fmt_dur(_span(cl)), "users": len(users)}))
    return out


def rule_bf002(logs, assets, cfg):
    fails = [e for e in logs if e["event_type"] == "login_failure" and e.get("src_ip") and e.get("username")]
    out = []
    for ip, evs in _group(fails, lambda e: e["src_ip"]).items():
        for cl in burst_clusters(evs, cfg.spray_window, cfg.spray_users, distinct=lambda e: e["username"]):
            users = sorted({e["username"] for e in cl})
            assets_hit = sorted({e["asset"] for e in cl})
            out.append(_mk("BF-002", cl, assets_hit[0], ratio_conf(len(users), cfg.spray_users, lo=0.6),
                           [f"{len(users)} different accounts failed login from {ip} within {fmt_dur(_span(cl))}",
                            f"Systems targeted: {', '.join(assets_hit)}",
                            "Few attempts per account is typical of password spraying (avoids lockouts)"],
                           src_ip=ip, facts={"count": len(cl), "users": len(users), "duration": fmt_dur(_span(cl))}))
    return out


def rule_bf003(logs, assets, cfg):
    auth = [e for e in logs if e["event_type"] in ("login_failure", "login_success")
            and e.get("src_ip") and e.get("username")]
    out = []
    for (user, ip), evs in _group(auth, lambda e: (e["username"], e["src_ip"])).items():
        recent = []
        for e in sorted(evs, key=lambda x: x["_ts"]):
            if e["event_type"] == "login_failure":
                recent.append(e)
                continue
            fails = [f for f in recent if e["_ts"] - f["_ts"] <= cfg.bf_success_window]
            if len(fails) >= cfg.bf_success_fails:
                cl = fails + [e]
                out.append(_mk("BF-003", cl, e["asset"], 0.9,
                               [f"{len(fails)} failed logins for {user} from {ip}, then a SUCCESSFUL login to {e['asset']}",
                                f"Failures and success were within {fmt_dur(e['_ts'] - fails[0]['_ts'])}",
                                "The account may now be controlled by the attacker"],
                               username=user, src_ip=ip,
                               facts={"count": len(fails), "duration": fmt_dur(e['_ts'] - fails[0]['_ts'])}))
            recent = []
    return out


# ----------------------------------------------------------------------------- EHR access
def _non_care_ehr(logs):
    return [e for e in logs if e["event_type"] == "ehr_record_access" and e.get("username")
            and not _det(e).get("care_relationship", True) and not _det(e).get("break_glass", False)]


def rule_ehr001(logs, assets, cfg):
    out = []
    for user, evs in _group(_non_care_ehr(logs), lambda e: e["username"]).items():
        for cl in burst_clusters(evs, cfg.ehr_bulk_window, cfg.ehr_bulk_patients,
                                 distinct=lambda e: _det(e).get("patient_id")):
            pts = sorted({_det(e).get("patient_id") for e in cl})
            dept = _det(cl[0]).get("user_department", "unknown")
            out.append(_mk("EHR-001", cl, cl[0]["asset"], ratio_conf(len(pts), cfg.ehr_bulk_patients, lo=0.6),
                           [f"{user} opened {len(pts)} different patient records in {fmt_dur(_span(cl))} "
                            f"with no documented care relationship",
                            f"User department: {dept}", f"Example record IDs: {', '.join(pts[:3])}"],
                           username=user, src_ip=cl[0].get("src_ip"),
                           facts={"count": len(pts), "duration": fmt_dur(_span(cl)), "department": dept}))
    return out


def rule_ehr002(logs, assets, cfg):
    off = [e for e in _non_care_ehr(logs) if after_hours(e["_ts"], cfg)]
    out = []
    for user, evs in _group(off, lambda e: e["username"]).items():
        for cl in burst_clusters(evs, cfg.ehr_after_hours_window, cfg.ehr_after_hours_min):
            lh = local_hour(cl[0]["_ts"], cfg.utc_offset_hours)
            out.append(_mk("EHR-002", cl, cl[0]["asset"], ratio_conf(len(cl), cfg.ehr_after_hours_min, lo=0.6, hi=0.9),
                           [f"{len(cl)} record accesses by {user} outside business hours (local hour {lh:02d}:00) "
                            f"with no care relationship",
                            f"Business hours are {cfg.business_start:02d}:00-{cfg.business_end:02d}:00 local time"],
                           username=user, src_ip=cl[0].get("src_ip"),
                           facts={"count": len(cl), "hour": f"{lh:02d}:00"}))
    return out


def rule_ehr003(logs, assets, cfg):
    vip = [e for e in _non_care_ehr(logs) if _det(e).get("vip")]
    out = []
    for user, evs in _group(vip, lambda e: e["username"]).items():
        for cl in chain_clusters(evs, 3600):
            off = any(after_hours(e["_ts"], cfg) for e in cl)
            out.append(_mk("EHR-003", cl, cl[0]["asset"], 0.85 + (0.1 if off else 0),
                           [f"{user} opened {len(cl)} VIP/restricted patient record(s) without a care relationship",
                            "Record IDs: " + ", ".join(sorted({_det(e).get('patient_id', '?') for e in cl}))],
                           username=user, src_ip=cl[0].get("src_ip"), facts={"count": len(cl)}))
    return out


# ----------------------------------------------------------------------------- malware
def rule_mal001(logs, assets, cfg):
    avs = [e for e in logs if e["event_type"] == "av_detection"]
    failed = [e for e in avs if _det(e).get("action") in ("detected_only", "quarantine_failed")]
    out, used = [], set()
    for asset, evs in _group(failed, lambda e: e["asset"]).items():
        for cl in chain_clusters(evs, 3600):
            names = sorted({_det(e).get("threat_name", "?") for e in cl})
            out.append(_mk("MAL-001", cl, asset, 0.9,
                           [f"Antivirus found {', '.join(names)} on {asset} but could not remove it "
                            f"(action: {_det(cl[0]).get('action')})",
                            f"User on the device: {cl[0].get('username') or 'unknown'}"],
                           username=cl[0].get("username"), src_ip=cl[0].get("src_ip"),
                           facts={"count": len(cl), "threat": names[0]}))
            used.update(id(e) for e in cl)
    rest = [e for e in avs if id(e) not in used]
    for asset, evs in _group(rest, lambda e: e["asset"]).items():
        for cl in burst_clusters(evs, cfg.av_outbreak_window, cfg.av_outbreak_count):
            out.append(_mk("MAL-001", cl, asset, 0.7,
                           [f"{len(cl)} antivirus detections on {asset} within {fmt_dur(_span(cl))} (possible outbreak)"],
                           severity="medium", facts={"count": len(cl), "threat": _det(cl[0]).get("threat_name", "?")}))
    return out


def rule_mal002(logs, assets, cfg):
    procs = []
    for e in logs:
        if e["event_type"] != "process_start":
            continue
        d = _det(e)
        cmd = (d.get("command_line") or "").lower()
        if (d.get("process") or "").lower() in ("powershell.exe", "pwsh.exe") and \
                ("-enc " in cmd or "-encodedcommand" in cmd):
            procs.append(e)
    out = []
    for asset, evs in _group(procs, lambda e: e["asset"]).items():
        for cl in chain_clusters(evs, 600):
            parent = (_det(cl[0]).get("parent") or "").lower()
            office = parent in cfg.office_parents
            out.append(_mk("MAL-002", cl, asset, 0.85 if office else 0.6,
                           [f"PowerShell with an encoded command was started by {parent or 'unknown'} on {asset}",
                            "Office/browser programs launching hidden encoded PowerShell is a common malware technique"
                            if office else "Encoded PowerShell is unusual outside of scripted administration"],
                           username=cl[0].get("username"), src_ip=cl[0].get("src_ip"),
                           severity=None if office else "medium", facts={"count": len(cl), "parent": parent}))
    return out


def rule_mal003(logs, assets, cfg):
    hits = [e for e in logs if e["event_type"] == "network_connection"
            and (e.get("dst_ip") in cfg.ioc_ips or _det(e).get("domain") in cfg.ioc_domains)]
    out = []
    for (asset, dst), evs in _group(hits, lambda e: (e["asset"], e.get("dst_ip") or _det(e).get("domain"))).items():
        for cl in chain_clusters(evs, 3600):
            out.append(_mk("MAL-003", cl, asset, 0.9,
                           [f"{asset} connected to known-bad indicator {dst} {len(cl)} time(s) over {fmt_dur(_span(cl))}",
                            "Indicator comes from the simulated threat-intelligence list"],
                           src_ip=cl[0].get("src_ip"), facts={"count": len(cl), "ioc": dst,
                                                              "duration": fmt_dur(_span(cl))}))
    return out


# ----------------------------------------------------------------------------- ransomware
def rule_ran001(logs, assets, cfg):
    bursts = [e for e in logs if e["event_type"] == "file_modified_burst"
              and (_det(e).get("extension") or "").lower() in cfg.ransom_exts]
    out = []
    for asset, evs in _group(bursts, lambda e: e["asset"]).items():
        for cl in chain_clusters(evs, cfg.ransom_gap):
            files = sum(int(_det(e).get("files_modified", 0)) for e in cl)
            if files >= cfg.ransom_files:
                out.append(_mk("RAN-001", cl, asset, ratio_conf(files, cfg.ransom_files, lo=0.7, hi=0.97),
                               [f"{files} files renamed/encrypted with extension {_det(cl[0]).get('extension')} "
                                f"on {asset} in {fmt_dur(_span(cl))}",
                                "Rapid mass modification with a new extension is the signature of ransomware"],
                               username=cl[0].get("username"), src_ip=cl[0].get("src_ip"),
                               facts={"count": files, "duration": fmt_dur(_span(cl))}))
    return out


def rule_ran002(logs, assets, cfg):
    hits = [e for e in logs if e["event_type"] == "shadow_copy_deleted"
            or (e["event_type"] == "service_stopped" and _det(e).get("service") in cfg.backup_services)]
    out = []
    for asset, evs in _group(hits, lambda e: e["asset"]).items():
        for cl in chain_clusters(evs, 900):
            what = sorted({"shadow copies deleted" if e["event_type"] == "shadow_copy_deleted"
                           else f"{_det(e).get('service')} stopped" for e in cl})
            out.append(_mk("RAN-002", cl, asset, 0.8,
                           [f"On {asset}: {'; '.join(what)}",
                            "Attackers remove recovery options before encrypting files"],
                           username=cl[0].get("username"), src_ip=cl[0].get("src_ip"),
                           facts={"actions": "; ".join(what)}))
    return out


def rule_ran003(logs, assets, cfg):
    notes = [e for e in logs if e["event_type"] == "ransom_note_created"]
    out = []
    for asset, evs in _group(notes, lambda e: e["asset"]).items():
        for cl in chain_clusters(evs, 900):
            out.append(_mk("RAN-003", cl, asset, 0.95,
                           [f"{len(cl)} ransom note file(s) created on {asset} (e.g. {_det(cl[0]).get('filename')})"],
                           username=cl[0].get("username"), src_ip=cl[0].get("src_ip"), facts={"count": len(cl)}))
    return out


# ----------------------------------------------------------------------------- privilege abuse
def rule_priv001(logs, assets, cfg):
    out = []
    for e in logs:
        d = _det(e)
        if e["event_type"] != "group_membership_change" or d.get("group") not in cfg.admin_groups \
                or d.get("action", "added") != "added":
            continue
        actor, target = e.get("username"), d.get("target_user")
        reasons = []
        if actor not in cfg.approved_admins:
            reasons.append(f"{actor} is not an approved administrator")
        if actor == target:
            reasons.append("the account added itself")
        late = after_hours(e["_ts"], cfg)
        if late:
            reasons.append("the change happened outside business hours")
        if not reasons:
            continue
        strong = actor not in cfg.approved_admins or actor == target
        out.append(_mk("PRIV-001", [e], e["asset"], 0.9 if strong else 0.65,
                       [f"{actor} added {target} to '{d.get('group')}'", "Why suspicious: " + "; ".join(reasons)],
                       username=actor, src_ip=e.get("src_ip"),
                       facts={"actor": actor, "target": target, "group": d.get("group"),
                              "reasons": "; ".join(reasons)}))
    return out


def rule_priv002(logs, assets, cfg):
    hits = [e for e in logs if e["event_type"] == "interactive_logon" and _det(e).get("account_type") == "service"]
    out = []
    for (asset, user), evs in _group(hits, lambda e: (e["asset"], e.get("username"))).items():
        for cl in chain_clusters(evs, 3600):
            out.append(_mk("PRIV-002", cl, asset, 0.75,
                           [f"Service account {user} logged on interactively to {asset}",
                            "Service accounts should run services, not be used like a person"],
                           username=user, src_ip=cl[0].get("src_ip"), facts={"count": len(cl)}))
    return out


def rule_priv003(logs, assets, cfg):
    hits = [e for e in logs if e["event_type"] == "audit_log_cleared"]
    out = []
    for (asset, user), evs in _group(hits, lambda e: (e["asset"], e.get("username"))).items():
        for cl in chain_clusters(evs, 3600):
            out.append(_mk("PRIV-003", cl, asset, 0.8,
                           [f"{user} cleared the {_det(cl[0]).get('log', 'Security')} log on {asset}",
                            "Clearing logs removes evidence of what happened"],
                           username=user, src_ip=cl[0].get("src_ip"), facts={"log": _det(cl[0]).get("log", "Security")}))
    return out


# ----------------------------------------------------------------------------- medical devices
def _device_events(logs, assets):
    return [e for e in logs if e["event_type"] == "device_network_connection"
            and assets.get(e["asset"]) is not None and assets[e["asset"]].type == "medical_device"]


def rule_dev001(logs, assets, cfg):
    hits = [e for e in _device_events(logs, assets)
            if _det(e).get("direction") == "outbound" and e.get("dst_ip") and not is_internal(e["dst_ip"])]
    out = []
    for (asset, dst), evs in _group(hits, lambda e: (e["asset"], e["dst_ip"])).items():
        for cl in chain_clusters(evs, 3600):
            ioc = dst in cfg.ioc_ips
            out.append(_mk("DEV-001", cl, asset, 0.85 + (0.1 if ioc else 0),
                           [f"{_det(cl[0]).get('device_name', 'A device')} in {asset} contacted external address {dst} "
                            f"{len(cl)} time(s) (port {cl[0].get('dst_port')})",
                            "Medical devices normally talk only to internal clinical systems"
                            + ("; the address is on the simulated threat-intel list" if ioc else "")],
                           src_ip=cl[0].get("src_ip"), facts={"count": len(cl), "dst": dst, "ioc": "yes" if ioc else "no"}))
    return out


def rule_dev002(logs, assets, cfg):
    hits = [e for e in _device_events(logs, assets)
            if _det(e).get("direction") == "inbound" and e.get("dst_port") in cfg.device_admin_ports
            and e.get("src_ip") not in cfg.device_admin_allowlist]
    out = []
    for (asset, src, port), evs in _group(hits, lambda e: (e["asset"], e["src_ip"], e["dst_port"])).items():
        for cl in chain_clusters(evs, 900):
            out.append(_mk("DEV-002", cl, asset, 0.8,
                           [f"{src} opened {len(cl)} remote-admin connection(s) (port {port}) to {asset}",
                            f"{src} is not on the approved clinical-engineering allow-list"],
                           src_ip=src, facts={"count": len(cl), "port": port}))
    return out


def rule_dev003(logs, assets, cfg):
    out = []
    for (asset, src), evs in _group(_device_events(logs, assets), lambda e: (e["asset"], e.get("src_ip"))).items():
        for cl in burst_clusters(evs, cfg.device_scan_window, cfg.device_scan_ports,
                                 distinct=lambda e: e.get("dst_port")):
            ports = {e.get("dst_port") for e in cl}
            out.append(_mk("DEV-003", cl, asset, ratio_conf(len(ports), cfg.device_scan_ports, lo=0.6),
                           [f"{src} tried {len(ports)} different ports within {fmt_dur(_span(cl))} "
                            f"(targets: {', '.join(sorted({str(e.get('dst_ip')) for e in cl})[:3])})",
                            "Rapid probing of many ports looks like network scanning"],
                           src_ip=src, facts={"count": len(ports), "duration": fmt_dur(_span(cl))}))
    return out


def rule_dev004(logs, assets, cfg):
    hits = [e for e in logs if e["event_type"] == "device_firmware_change" and not _det(e).get("maintenance_window", False)]
    out = []
    for e in hits:
        d = _det(e)
        out.append(_mk("DEV-004", [e], e["asset"], 0.7,
                       [f"Firmware on {d.get('device_name', 'a device')} ({e['asset']}) changed from "
                        f"{d.get('old_version', '?')} to {d.get('new_version', '?')} outside a maintenance window",
                        f"Initiated by: {e.get('username') or 'unknown'}"],
                       username=e.get("username"), facts={"old": d.get("old_version"), "new": d.get("new_version")}))
    return out


RULE_FUNCS = [rule_bf001, rule_bf002, rule_bf003, rule_ehr001, rule_ehr002, rule_ehr003, rule_mal001, rule_mal002,
              rule_mal003, rule_ran001, rule_ran002, rule_ran003, rule_priv001, rule_priv002, rule_priv003,
              rule_dev001, rule_dev002, rule_dev003, rule_dev004]


def prepare(logs):
    """Copy logs and add the internal epoch timestamp `_ts` (the originals are untouched)."""
    out = []
    for l in logs:
        c = dict(l)
        c["_ts"] = parse_ts(l["timestamp"])
        out.append(c)
    out.sort(key=lambda e: (e["_ts"], e.get("log_id", "")))
    return out


def run_rules(logs, assets, cfg=None):
    cfg = cfg or DetectionConfig()
    prepared = prepare(logs)
    findings = []
    for fn in RULE_FUNCS:
        findings.extend(fn(prepared, assets, cfg))
    findings.sort(key=lambda f: (f.first_ts, f.rule_id))
    return findings
