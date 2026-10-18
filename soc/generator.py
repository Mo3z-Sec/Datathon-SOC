"""Synthetic hospital security log generator.

EVERYTHING produced here is SIMULATED. No real patient data, hostnames or public IP
addresses are used:
  * patient IDs look like SIM-PT-00123
  * usernames are fictional (sim.nurse04, sim.clerk12, ...)
  * "internet" addresses come only from the reserved documentation ranges
    192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (RFC 5737)
Output is deterministic for a given seed/day/offset.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

from .assets import host_ip

SCENARIOS = {
    "ransomware": "Phishing payload, backup tampering and mass file encryption on the Lab System",
    "ehr_access": "After-hours bulk snooping and a VIP chart lookup with no care relationship",
    "brute_force": "Password guessing then a successful VPN login, plus a password-spraying run",
    "malware": "Failed antivirus quarantine, encoded PowerShell and command-and-control beaconing",
    "privilege_abuse": "Self-granted Domain Admin, service-account logon and cleared audit log",
    "device_anomaly": "Infusion pump talking to the internet, RDP into a device, port scan, firmware change",
}

# Which detection rules each scenario is designed to trigger (used by tests and the UI).
EXPECTED_RULES = {
    "ransomware": ["MAL-002", "RAN-001", "RAN-002", "RAN-003"],
    "ehr_access": ["EHR-001", "EHR-002", "EHR-003"],
    "brute_force": ["BF-001", "BF-002", "BF-003"],
    "malware": ["MAL-001", "MAL-002", "MAL-003"],
    "privilege_abuse": ["PRIV-001", "PRIV-002", "PRIV-003"],
    "device_anomaly": ["DEV-001", "DEV-002", "DEV-003", "DEV-004"],
}

EXTERNAL_BENIGN = ["192.0.2.10", "192.0.2.25", "192.0.2.80", "192.0.2.131"]
ATTACKER_1, ATTACKER_2 = "203.0.113.45", "203.0.113.99"
C2_IP, DEVICE_C2_IP = "198.51.100.77", "198.51.100.200"
JUMP_HOST = "10.50.0.5"  # approved clinical-engineering jump host

NURSES = [f"sim.nurse{n:02d}" for n in range(1, 9)]
DOCTORS = [f"sim.dr{n:02d}" for n in range(1, 7)]
CLERKS = [f"sim.clerk{n:02d}" for n in range(1, 7)]
STAFF = NURSES + DOCTORS + CLERKS + ["sim.lab03", "sim.pharm02", "sim.admin01"]
DEPTS = ["Cardiology", "Oncology", "Emergency", "Pediatrics", "Radiology", "Surgery"]


class _Builder:
    def __init__(self, assets, rng, day, offset):
        self.assets, self.rng, self.day, self.offset = assets, rng, day, offset
        self.logs = []

    def local(self, hh, mm=0, ss=0):
        base = datetime(self.day.year, self.day.month, self.day.day, tzinfo=timezone.utc)
        return base + timedelta(hours=hh - self.offset, minutes=mm, seconds=ss)

    def ip(self, asset, n):
        return host_ip(self.assets[asset], n)

    def add(self, when, source, asset, event_type, scenario=None, username=None, src_ip=None,
            dst_ip=None, dst_port=None, outcome=None, message="", details=None):
        if not message:
            bits = [event_type]
            if username:
                bits.append(f"user={username}")
            if src_ip:
                bits.append(f"src={src_ip}")
            if dst_ip:
                bits.append(f"dst={dst_ip}" + (f":{dst_port}" if dst_port else ""))
            if outcome:
                bits.append(f"outcome={outcome}")
            message = " ".join(bits)
        self.logs.append({
            "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": source, "asset": asset, "event_type": event_type,
            "username": username, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
            "outcome": outcome, "message": message, "details": details or {},
            "simulated": True, "sim_scenario": scenario,
        })


def _patient(n):
    return f"SIM-PT-{n:05d}"


def _benign(b, count):
    r = b.rng
    ws_nurse = [b.ip("Nurse Workstation", i) for i in range(1, 9)]
    ws_admin = [b.ip("Admin Office PC", i) for i in range(1, 9)]
    login_targets = ["EHR Server", "Nurse Workstation", "Admin Office PC", "Lab System",
                     "Finance System", "PACS Imaging", "Pharmacy System"]
    procs = [
        ("outlook.exe", "explorer.exe", "outlook.exe /recycle"),
        ("chrome.exe", "explorer.exe", "chrome.exe --profile-directory=Default"),
        ("powershell.exe", "ccmexec.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\inventory.ps1"),
        ("excel.exe", "explorer.exe", "excel.exe /e"),
    ]

    def when():
        if r.random() < 0.85:
            return b.local(r.randint(7, 18), r.randint(0, 59), r.randint(0, 59))
        return b.local(r.randint(0, 23), r.randint(0, 59), r.randint(0, 59))

    kinds = ["login"] * 40 + ["ehr"] * 25 + ["proc"] * 10 + ["net"] * 10 + ["device"] * 8 + ["firmware", "jump"]
    for _ in range(count):
        k = r.choice(kinds)
        t = when()
        if k == "login":
            target = r.choice(login_targets)
            user = r.choice(STAFF)
            src = r.choice(ws_nurse + ws_admin)
            b.add(t, "auth", target, "login_success", username=user, src_ip=src, outcome="success",
                  details={"method": "rdp" if target.endswith("PC") else "web"})
        elif k == "ehr":
            user = r.choice(NURSES + DOCTORS)
            b.add(t, "ehr", "EHR Server", "ehr_record_access", username=user,
                  src_ip=r.choice(ws_nurse), outcome="success",
                  details={"patient_id": _patient(r.randint(100, 4000)),
                           "record_type": r.choice(["chart", "lab", "imaging", "meds"]),
                           "user_department": r.choice(DEPTS), "patient_department": r.choice(DEPTS),
                           "care_relationship": True, "vip": False, "break_glass": False})
        elif k == "proc":
            p, parent, cmd = r.choice(procs)
            asset = r.choice(["Nurse Workstation", "Admin Office PC"])
            b.add(t, "endpoint", asset, "process_start", username=r.choice(STAFF),
                  src_ip=b.ip(asset, r.randint(1, 8)),
                  details={"process": p, "parent": parent, "command_line": cmd})
        elif k == "net":
            asset = r.choice(["Nurse Workstation", "Admin Office PC"])
            ext = r.random() < 0.6
            b.add(t, "network", asset, "network_connection", src_ip=b.ip(asset, r.randint(1, 8)),
                  dst_ip=r.choice(EXTERNAL_BENIGN) if ext else b.ip("EHR Server", 1),
                  dst_port=443, details={"direction": "outbound" if ext else "internal",
                                         "protocol": "tcp", "bytes_out": r.randint(400, 90000)})
        elif k == "device":
            dev = r.choice(["Infusion Pump Network", "MRI Scanner", "Patient Monitor Network"])
            dst_asset, port = r.choice([("PACS Imaging", 11112), ("EHR Server", 2575), ("EHR Server", 443)])
            b.add(t, "device", dev, "device_network_connection", src_ip=b.ip(dev, r.randint(20, 60)),
                  dst_ip=b.ip(dst_asset, 1), dst_port=port,
                  details={"direction": "internal", "protocol": "tcp", "device_name": f"DEV-{r.randint(10, 99)}"})
        elif k == "firmware":
            b.add(t, "device", "MRI Scanner", "device_firmware_change", username="sim.clinical-eng01",
                  details={"device_name": "MRI-01", "old_version": "4.2.1", "new_version": "4.2.2",
                           "maintenance_window": True})
        else:  # approved jump host RDP into a device (allow-listed, must NOT alert)
            dev = r.choice(["Infusion Pump Network", "Patient Monitor Network"])
            b.add(t, "device", dev, "device_network_connection", src_ip=JUMP_HOST,
                  dst_ip=b.ip(dev, r.randint(20, 60)), dst_port=3389,
                  details={"direction": "inbound", "protocol": "tcp", "device_name": "DEV-MAINT"})
    # A few isolated typo failures. Total is capped at 4 so benign noise can never reach any
    # brute-force threshold (guaranteed by construction).
    for i in range(min(4, max(1, count // 50))):
        b.add(when(), "auth", r.choice(["EHR Server", "Admin Office PC"]), "login_failure",
              username=r.choice(STAFF), src_ip=r.choice(ws_nurse + ws_admin), outcome="failure",
              details={"method": "web", "reason": "bad_password"})
    # Two well-separated, successfully quarantined nuisance detections (must NOT alert).
    for hh in (10, 15):
        b.add(b.local(hh, 20, 0), "endpoint", "Admin Office PC", "av_detection", username=r.choice(CLERKS),
              src_ip=b.ip("Admin Office PC", 4),
              details={"threat_name": "PUA.Sim.Toolbar", "action": "quarantined"})
    # An approved admin legitimately adds someone to an admin group during business hours.
    b.add(b.local(11, 0, 5), "directory", "Domain Controller", "group_membership_change",
          username="sim.admin01", details={"target_user": "sim.admin03", "group": "Domain Admins", "action": "added"})
    # A break-glass emergency access (no care relationship documented yet, flagged break_glass).
    b.add(b.local(3, 12, 0), "ehr", "EHR Server", "ehr_record_access", username="sim.dr03",
          src_ip=b.ip("Nurse Workstation", 2), outcome="success",
          details={"patient_id": _patient(777), "record_type": "chart", "user_department": "Emergency",
                   "patient_department": "Emergency", "care_relationship": False, "vip": False, "break_glass": True})


def _ransomware(b):
    r, A, victim = b.rng, "Lab System", "sim.lab03"
    src = b.ip(A, 7)
    b.add(b.local(14, 2, 10), "endpoint", A, "process_start", "ransomware", username=victim, src_ip=src,
          details={"process": "powershell.exe", "parent": "winword.exe",
                   "command_line": "powershell.exe -nop -w hidden -enc U0lNVUxBVEVEX1BBWUxPQUQ="})
    b.add(b.local(14, 21, 5), "endpoint", A, "service_stopped", "ransomware", username=victim, src_ip=src,
          details={"service": "BackupAgent"})
    b.add(b.local(14, 21, 40), "endpoint", A, "shadow_copy_deleted", "ransomware", username=victim, src_ip=src,
          details={"command_line": "vssadmin delete shadows /all /quiet"})
    for i in range(4):
        b.add(b.local(14, 23, i * 30), "endpoint", A, "file_modified_burst", "ransomware", username=victim,
              src_ip=src, details={"files_modified": r.randint(350, 600), "extension": ".locked",
                                   "window_seconds": 30})
    for i in range(2):
        b.add(b.local(14, 25, 10 + i * 20), "endpoint", A, "ransom_note_created", "ransomware", username=victim,
              src_ip=src, details={"filename": "README_SIM_RESTORE.txt", "path": f"C:\\Shares\\Lab\\dir{i}"})
    for i in range(5):
        b.add(b.local(14, 24, i * 12), "network", A, "network_connection", "ransomware", src_ip=src,
              dst_ip=b.ip("Nurse Workstation", i + 1), dst_port=445,
              details={"direction": "internal", "protocol": "smb", "bytes_out": r.randint(2000, 90000)})


def _brute_force(b):
    r, vpn = b.rng, "VPN Gateway"
    t = b.local(1, 40, 0)
    for _ in range(14):
        t += timedelta(seconds=r.randint(12, 25))
        b.add(t, "auth", vpn, "login_failure", "brute_force", username="sim.helpdesk05", src_ip=ATTACKER_1,
              outcome="failure", details={"method": "vpn", "reason": "bad_password"})
    b.add(t + timedelta(seconds=30), "auth", vpn, "login_success", "brute_force", username="sim.helpdesk05",
          src_ip=ATTACKER_1, outcome="success", details={"method": "vpn"})
    t = b.local(3, 5, 0)
    for i in range(9):
        t += timedelta(seconds=r.randint(55, 70))
        b.add(t, "auth", vpn, "login_failure", "brute_force", username=f"sim.user{i + 1:02d}", src_ip=ATTACKER_2,
              outcome="failure", details={"method": "vpn", "reason": "bad_password"})


def _ehr_access(b):
    r, src = b.rng, b.ip("Admin Office PC", 12)
    t = b.local(22, 48, 0)
    for i in range(32):
        t += timedelta(seconds=r.randint(10, 20))
        b.add(t, "ehr", "EHR Server", "ehr_record_access", "ehr_access", username="sim.clerk12", src_ip=src,
              outcome="success",
              details={"patient_id": _patient(2000 + i * 7), "record_type": "chart",
                       "user_department": "Administration", "patient_department": r.choice(DEPTS),
                       "care_relationship": False, "vip": False, "break_glass": False})
    b.add(b.local(10, 35, 0), "ehr", "EHR Server", "ehr_record_access", "ehr_access", username="sim.nurse04",
          src_ip=b.ip("Nurse Workstation", 4), outcome="success",
          details={"patient_id": _patient(90001), "record_type": "chart", "user_department": "Pediatrics",
                   "patient_department": "Surgery", "care_relationship": False, "vip": True, "break_glass": False})


def _malware(b):
    r, A, user = b.rng, "Admin Office PC", "sim.clerk07"
    src = b.ip(A, 31)
    b.add(b.local(9, 12, 0), "endpoint", A, "av_detection", "malware", username=user, src_ip=src,
          details={"threat_name": "Trojan.Sim.Dropper", "action": "quarantine_failed",
                   "file": "C:\\Users\\sim.clerk07\\Downloads\\invoice_sim.exe", "sha256": "sim" + "0" * 61})
    b.add(b.local(9, 13, 0), "endpoint", A, "process_start", "malware", username=user, src_ip=src,
          details={"process": "powershell.exe", "parent": "excel.exe",
                   "command_line": "powershell.exe -w hidden -EncodedCommand U0lNVUxBVEVE"})
    t = b.local(9, 14, 0)
    for _ in range(12):
        b.add(t, "network", A, "network_connection", "malware", src_ip=src, dst_ip=C2_IP, dst_port=443,
              details={"direction": "outbound", "protocol": "tcp", "bytes_out": r.randint(500, 900)})
        t += timedelta(minutes=10, seconds=r.randint(-20, 20))


def _privilege_abuse(b):
    b.add(b.local(2, 15, 0), "directory", "Domain Controller", "group_membership_change", "privilege_abuse",
          username="sim.helpdesk05", details={"target_user": "sim.helpdesk05", "group": "Domain Admins",
                                              "action": "added"})
    b.add(b.local(2, 21, 0), "directory", "EHR Server", "interactive_logon", "privilege_abuse",
          username="svc_sim_backup", src_ip=b.ip("Domain Controller", 2), outcome="success",
          details={"account_type": "service"})
    b.add(b.local(2, 40, 0), "directory", "Domain Controller", "audit_log_cleared", "privilege_abuse",
          username="sim.helpdesk05", details={"log": "Security"})


def _device_anomaly(b):
    r = b.rng
    pump = "Infusion Pump Network"
    for mm in (10, 25, 40):
        b.add(b.local(5, mm, 0), "device", pump, "device_network_connection", "device_anomaly",
              src_ip=b.ip(pump, 23), dst_ip=DEVICE_C2_IP, dst_port=443,
              details={"direction": "outbound", "protocol": "tcp", "device_name": "IP-PUMP-23"})
    for s in (0, 90):
        b.add(b.local(5, 12, s), "device", pump, "device_network_connection", "device_anomaly",
              src_ip=b.ip("Admin Office PC", 5), dst_ip=b.ip(pump, 31), dst_port=3389,
              details={"direction": "inbound", "protocol": "tcp", "device_name": "IP-PUMP-31"})
    mon, t = "Patient Monitor Network", b.local(16, 30, 0)
    for i in range(24):
        b.add(t + timedelta(seconds=i * 3), "device", mon, "device_network_connection", "device_anomaly",
              src_ip=b.ip(mon, 7), dst_ip=b.ip("EHR Server", 1), dst_port=1000 + i * 37,
              details={"direction": "internal", "protocol": "tcp", "device_name": "MON-07"})
    b.add(b.local(23, 5, 0), "device", "MRI Scanner", "device_firmware_change", "device_anomaly",
          username="unknown", details={"device_name": "MRI-01", "old_version": "4.2.2", "new_version": "4.9.0-unsigned",
                                       "maintenance_window": False})


_BUILDERS = {"ransomware": _ransomware, "ehr_access": _ehr_access, "brute_force": _brute_force,
             "malware": _malware, "privilege_abuse": _privilege_abuse, "device_anomaly": _device_anomaly}


def generate(assets, seed=42, day=None, benign=300, scenarios=None, utc_offset_hours=0.0):
    """Return a time-sorted list of simulated log dicts."""
    if scenarios is None:
        scenarios = list(SCENARIOS)
    unknown = [s for s in scenarios if s not in SCENARIOS]
    if unknown:
        raise ValueError(f"Unknown scenario(s): {unknown}. Valid: {sorted(SCENARIOS)}")
    if benign < 0 or benign > 5000:
        raise ValueError("benign must be between 0 and 5000")
    if day is None:
        day = (datetime.now(timezone.utc) - timedelta(days=1)).date()
    rng = random.Random(seed)
    b = _Builder(assets, rng, day, utc_offset_hours)
    if benign:
        _benign(b, benign)
    for name in scenarios:
        _BUILDERS[name](b)
    ordered = sorted(enumerate(b.logs), key=lambda p: (p[1]["timestamp"], p[0]))
    out = []
    for n, (_, log) in enumerate(ordered, 1):
        log["log_id"] = f"SIM-{seed}-{n:05d}"
        out.append(log)
    return out


def to_jsonl(logs) -> str:
    return "\n".join(json.dumps(l, sort_keys=True) for l in logs) + "\n"
