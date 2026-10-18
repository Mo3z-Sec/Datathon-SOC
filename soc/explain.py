"""Plain-English alert explanations.

Always available offline (deterministic templates). If an external AI API is configured
(SOC_AI_PROVIDER=anthropic + key) it is asked to rewrite the explanation; on ANY failure
(no network, bad key, timeout, malformed answer) the offline explanation is used instead.

Privacy: the AI prompt contains only the alert's summary fields (rule, score factors,
evidence sentences, asset name/type) - never raw log lines. Keep AI off for real data
unless your organisation has approved it.
"""
from __future__ import annotations

import json
import re
import urllib.request

DISCLAIMER = ("Advisory only. This system is read-only: it never changes, blocks or isolates anything. "
              "Containment steps must be carried out by authorised staff under your incident procedures.")
GROUPS = ("investigate", "triage", "contain", "escalate")

RULE_TEXT = {
    "BF-001": ("Someone at {src_ip} tried to sign in to {asset} {count} times and failed, within {duration}. "
               "Rapid repeated failures like this usually mean an automated password-guessing tool.",
               "If one guess works, the attacker gets a legitimate login to {asset} and can explore the hospital network from inside."),
    "BF-002": ("{src_ip} attempted to log in with {users} different accounts in {duration}, with only a few tries each. "
               "This is called password spraying and is designed to avoid account lockouts.",
               "Password spraying often succeeds against weak or reused passwords, and one compromised account can expose patient systems."),
    "BF-003": ("{username} failed to log in {count} times from {src_ip} and then succeeded on {asset}. "
               "A success right after many failures suggests the password was guessed.",
               "This is the point where a brute-force attempt becomes an actual compromise: the attacker may now be using {username}'s access."),
    "EHR-001": ("{username} ({department}) opened {count} different patient records in {duration} without a documented reason to be involved in their care. "
                "Normal clinical work does not usually look like this.",
                "Mass viewing of records is a patient-privacy breach risk (it may need regulatory reporting) and may indicate snooping or data theft."),
    "EHR-002": ("{username} opened {count} patient records around {hour} local time, outside normal working hours, with no care relationship.",
                "After-hours access to charts you are not treating is a common sign of snooping or a compromised account."),
    "EHR-003": ("{username} opened a restricted VIP patient record without a care relationship.",
                "VIP and sensitive records are high-value targets for curiosity and for leaks to the media."),
    "MAL-001": ("{evidence0} A person needs to confirm the file is really gone.",
                "Malware that survives cleanup can steal data, spread to other computers or prepare a ransomware attack."),
    "MAL-002": ("A program ({parent}) on {asset} started PowerShell with a hidden, encoded command. "
                "This is a common way for malicious documents to launch malware.",
                "Encoded commands hide what is being run; this often marks the very first step of a ransomware or data-theft attack."),
    "MAL-003": ("{asset} contacted {ioc}, an address on the threat-intelligence list, {count} time(s) over {duration}. "
                "Regular check-ins like this look like malware reporting to its controller.",
                "Command-and-control traffic means an attacker may be directing the device remotely."),
    "RAN-001": ("{count} files on {asset} were renamed or encrypted in {duration}. That speed and the new file extension match ransomware.",
                "Ransomware can stop clinical systems, delay patient care and force the hospital onto downtime procedures."),
    "RAN-002": ("On {asset}: {actions}. Attackers remove backups and shadow copies so data cannot be restored without paying.",
                "Without these recovery options, recovery is slower and more disruptive to patient care."),
    "RAN-003": ("{count} ransom note file(s) were created on {asset}. Files are already being held for ransom.",
                "This confirms ransomware impact; hospital downtime procedures and the incident response plan may need to be activated."),
    "PRIV-001": ("{actor} added {target} to the privileged group '{group}'. Why this looks wrong: {reasons}.",
                 "Administrator rights let someone control accounts, systems and security settings across the hospital."),
    "PRIV-002": ("The service account {username} logged on interactively to {asset}. Service accounts are meant to run software, not be used like a person.",
                 "Attackers like service accounts because they are powerful and rarely watched."),
    "PRIV-003": ("{username} cleared the {log} log on {asset}. Clearing the log removes the record of recent activity.",
                 "Attackers clear logs to hide their tracks, which makes it much harder to investigate and prove what happened."),
    "DEV-001": ("A medical device in {asset} contacted an internet address ({dst}) {count} time(s). Medical devices should only talk to internal clinical systems.",
                "A compromised device could leak data, be remotely controlled or be used to reach other hospital systems, and may affect patient safety."),
    "DEV-002": ("{src_ip} opened a remote-administration connection (port {port}) to a device in {asset}. This address is not on the approved list.",
                "Unapproved remote access to a medical device could allow tampering with how it behaves, which is a patient-safety concern."),
    "DEV-003": ("A device in {asset} tried {count} different network ports in {duration}. That is typical of scanning for weaknesses.",
                "A device that scans the network is probably compromised and is looking for more systems to attack."),
    "DEV-004": ("Firmware on a device in {asset} changed from {old} to {new} outside a planned maintenance window.",
                "Unplanned firmware changes can introduce malicious or untested software to equipment used for patient care."),
}

CATEGORY_STEPS = {
    "brute_force": {
        "investigate": ["Review the failed and successful logins in the evidence table (times, accounts, source address).",
                        "Check whether the source address belongs to a known user, vendor or VPN pool.",
                        "Look at what the targeted account did after any successful login."],
        "triage": ["Confirm with the account owner whether they were trying to log in.",
                   "Treat a success after many failures as a confirmed compromise until proven otherwise.",
                   "Check whether the same source address hit other systems in the last 24 hours."],
        "contain": ["Ask the network team to block the source address at the perimeter (this tool will not do it).",
                    "Reset the password and end active sessions for any account that logged in successfully.",
                    "Enable or tighten account lockout and multi-factor authentication on the targeted service."],
        "escalate": ["Escalate to the incident lead if a login succeeded or the account is privileged.",
                     "Notify the security manager if several systems or accounts were targeted."]},
    "ehr_access": {
        "investigate": ["Pull the user's full EHR access audit trail for the last 30 days.",
                        "Compare the opened records with the user's department, shift and assigned patients.",
                        "Check whether the access came from the user's usual workstation and location."],
        "triage": ["Ask the user's manager whether there was a legitimate reason (cover shift, audit, emergency).",
                   "Look for break-glass justifications recorded for these records.",
                   "Decide whether this is snooping (a privacy/HR matter) or a compromised account (a security incident)."],
        "contain": ["Ask the EHR administrator to restrict or suspend the account if misuse is likely, through normal change control.",
                    "Reset credentials if account compromise is suspected."],
        "escalate": ["Notify the Privacy/Compliance Officer: bulk or VIP access may need a breach assessment.",
                     "Involve HR if misuse by a staff member is confirmed."]},
    "malware": {
        "investigate": ["Identify the file, user and process involved and how it arrived (email, download, USB).",
                        "Check the endpoint protection console for other detections on the same device.",
                        "Search for the same file or network address on other computers."],
        "triage": ["Confirm whether the detection is a false positive using a second source (sandbox or vendor reputation).",
                   "Check whether the device made unusual connections after the detection."],
        "contain": ["Ask IT to disconnect the affected computer from the network once clinical needs are checked.",
                    "Block the malicious address or file hash in security tooling.",
                    "Preserve the device for forensics rather than wiping it straight away."],
        "escalate": ["Escalate to the incident lead if there is traffic to a known-bad address or more than one device is affected."]},
    "ransomware": {
        "investigate": ["Identify the first affected device and the earliest suspicious event (often a phishing document).",
                        "Check which shares and systems the device can reach to see how far encryption could spread.",
                        "Verify that the latest good backups are intact and offline."],
        "triage": ["Treat this as a critical incident until proven otherwise.",
                   "Ask clinical leads which patient-care workflows depend on the affected systems."],
        "contain": ["Ask IT to isolate the affected device(s) from the network immediately; do not power them off, as memory evidence is lost.",
                    "Disable the affected user account and block lateral movement paths such as SMB between segments.",
                    "Protect backups: disconnect backup servers from the network until the scope is known."],
        "escalate": ["Activate the hospital incident response plan and notify the incident commander now.",
                     "Inform clinical leadership so downtime procedures can start.",
                     "Notify executives, legal and regulators according to the breach-notification policy."]},
    "privilege_abuse": {
        "investigate": ["Review who made the change and which session or ticket authorised it.",
                        "List everything the account did after receiving elevated rights.",
                        "Check domain controller logs for other changes around the same time (new accounts, policy changes)."],
        "triage": ["Confirm with the IT team whether this was an approved change.",
                   "Check whether the acting account was recently used from an unusual place."],
        "contain": ["Ask the identity team to remove the unauthorised membership and disable the account through change control.",
                    "Reset credentials for the accounts involved and review privileged group membership."],
        "escalate": ["Escalate to the incident lead if the change was not authorised.",
                     "Involve the security manager: audit-log tampering may indicate an active intruder."]},
    "device_anomaly": {
        "investigate": ["Identify the device, its owner and its clinical function using the asset inventory.",
                        "Review the device's recent network connections and configuration changes.",
                        "Check whether the manufacturer or Clinical Engineering planned this activity."],
        "triage": ["Confirm with Clinical Engineering whether the activity is expected (maintenance, vendor remote support).",
                   "Assess patient-safety impact with the clinical lead before any action."],
        "contain": ["Ask the network team to block the suspicious traffic at the firewall rather than touching the device.",
                    "Do not power off, reboot or factory-reset clinical devices without Clinical Engineering and the charge nurse.",
                    "Switch to manual monitoring for affected patients if the device is suspected to be unsafe."],
        "escalate": ["Escalate to the incident lead and the Clinical Engineering lead immediately for any suspected tampering.",
                     "Report to the device manufacturer and, if required, regulators for safety-related incidents."]},
}


class _Safe(dict):
    def __missing__(self, key):
        return "unknown"


def _fmt(template, alert):
    values = _Safe(alert.get("facts") or {})
    for k in ("asset", "username", "src_ip"):
        values.setdefault(k, alert.get(k) or "unknown")
    values["evidence0"] = (alert.get("evidence") or [""])[0]
    return template.format_map(values)


def offline_explanation(alert, asset=None):
    summary_t, why_t = RULE_TEXT.get(alert["rule_id"], ("{evidence0}", "Review this alert with your team."))
    steps = {g: list(CATEGORY_STEPS[alert["category"]][g]) for g in GROUPS}
    if asset is not None and asset.type == "medical_device":
        steps["contain"].append("This is a clinical device: coordinate every containment step with Clinical Engineering first.")
    pct = round(float(alert.get("confidence", 0)) * 100)
    return {
        "summary": _fmt(summary_t, alert),
        "why_it_matters": _fmt(why_t, alert),
        "confidence_note": (f"{alert.get('confidence_label', '')} confidence ({pct}%). Detection uses fixed rules over the logs, "
                            "so check the evidence and context before acting."),
        "steps": steps,
        "source": "offline",
        "disclaimer": DISCLAIMER,
    }


# ----------------------------------------------------------------------------- optional AI
API_URL = "https://api.anthropic.com/v1/messages"
SYSTEM_PROMPT = (
    "You are a hospital security operations assistant helping a SOC analyst. Explain the alert in plain English "
    "for a busy non-specialist. Use ONLY the facts provided; do not invent details. Never recommend actions that "
    "could harm patients (for example powering off clinical devices) without clinical engineering approval. "
    "All containment actions are performed by humans; you perform none. Reply with ONLY a JSON object: "
    '{"summary": str, "why_it_matters": str, "steps": {"investigate": [str], "triage": [str], "contain": [str], '
    '"escalate": [str]}} with at most 5 short items per list.')


class AIError(Exception):
    pass


def build_ai_prompt(alert, asset, baseline):
    payload = {
        "rule": alert["rule_id"], "title": alert["title"], "category": alert["category"],
        "risk_score_1_to_10": alert["score"], "confidence": alert.get("confidence"),
        "score_factors": [{"factor": b["factor"], "points": b["points"], "why": b["detail"]} for b in alert["breakdown"]],
        "evidence": alert["evidence"], "first_seen": alert["first_seen"], "last_seen": alert["last_seen"],
        "asset": {"name": alert["asset"], "type": getattr(asset, "type", "unknown"),
                  "criticality_1_to_5": getattr(asset, "criticality", None),
                  "department": getattr(asset, "department", ""), "patient_care": getattr(asset, "patient_care", None)},
        "related_detections": [r["title"] for r in alert.get("related", [])],
        "baseline_explanation": baseline["summary"],
        "data_is_simulated": True,
    }
    return json.dumps(payload, indent=1)


def _http_post(url, headers, body, timeout):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
        return resp.read().decode("utf-8")


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _clean_text(v, limit):
    if not isinstance(v, str) or not v.strip():
        raise AIError("expected non-empty text")
    return _CTRL.sub("", v).strip()[:limit]


def parse_ai_answer(text, baseline):
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text).strip()
    try:
        obj = json.loads(text)
    except ValueError as exc:
        raise AIError("AI answer was not valid JSON") from exc
    if not isinstance(obj, dict):
        raise AIError("AI answer was not a JSON object")
    steps_in = obj.get("steps") if isinstance(obj.get("steps"), dict) else {}
    steps = {}
    for g in GROUPS:
        items = steps_in.get(g)
        if isinstance(items, list) and items:
            steps[g] = [_clean_text(i, 300) for i in items[:6] if isinstance(i, str) and i.strip()] or baseline["steps"][g]
        else:
            steps[g] = baseline["steps"][g]
    return {"summary": _clean_text(obj.get("summary"), 1200),
            "why_it_matters": _clean_text(obj.get("why_it_matters"), 1200), "steps": steps}


def ai_explanation(alert, asset, settings, baseline, post=None):
    post = post or _http_post
    body = json.dumps({
        "model": settings.ai_model, "max_tokens": 900, "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": build_ai_prompt(alert, asset, baseline)}],
    }).encode("utf-8")
    headers = {"content-type": "application/json", "x-api-key": settings.ai_api_key,
               "anthropic-version": "2023-06-01"}
    try:
        raw = post(API_URL, headers, body, settings.ai_timeout)
        data = json.loads(raw)
        text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
    except AIError:
        raise
    except Exception as exc:  # network, HTTP error, bad JSON envelope ...
        raise AIError(f"{exc.__class__.__name__}") from exc
    parsed = parse_ai_answer(text, baseline)
    out = dict(baseline)
    out.update(parsed)
    out["source"] = "ai"
    out["ai_model"] = settings.ai_model
    return out


def explain_alert(alert, asset, settings, use_ai=True, post=None):
    """Offline explanation, upgraded with AI when enabled. Never raises because of the AI."""
    base = offline_explanation(alert, asset)
    if not (use_ai and settings.ai_enabled):
        return base
    try:
        return ai_explanation(alert, asset, settings, base, post=post)
    except AIError as exc:
        base["source"] = "offline"
        base["ai_note"] = f"External AI unavailable ({exc}); showing the built-in offline explanation."
        return base
