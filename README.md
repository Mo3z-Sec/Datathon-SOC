# Hospital SOC Alert System (simulated data)

A small, working security-operations dashboard for a hospital. It generates **realistic but entirely fictional**
security logs, detects suspicious activity with **fixed, explainable rules**, gives every alert a **1-10 risk score
with a visible breakdown**, explains each alert **in plain English**, and lets analysts **search, filter, change
status, add notes and export**.

> **SIMULATED DATA ONLY.** No real patients, systems or incidents. The application refuses to load logs that are not
> marked `simulated: true`, never connects to any hospital system, and never blocks, isolates or changes anything.
> Recommended containment steps are advice for humans.

* Stack: Python 3.9+ - FastAPI - SQLite (standard library) - plain HTML/CSS/JavaScript (no CDN, no build step).
* Works on any Linux; written for an IBM **LinuxONE** server (s390x). All dependencies are pure Python or publish s390x wheels.

---------------------------------------------------------------------------------------------------

## 1. What "Linux One" means here, and what to verify first

**IBM LinuxONE** is IBM's line of enterprise servers (the IBM Z family) that run **Linux** on the **s390x** CPU
architecture (64-bit, big-endian). You normally get a Linux virtual machine (Red Hat Enterprise Linux, SUSE or Ubuntu),
for example from the IBM LinuxONE Community Cloud. This project was written on the assumption that your server is:

| Assumption | Why it matters |
|---|---|
| Ubuntu (or another Linux with `apt`/`dnf`/`zypper`) | package-install commands differ per family |
| CPU architecture `s390x` | pip must find s390x wheels or build from source; Docker images must support `linux/s390x` |
| Python 3.9 or newer (Ubuntu 24.04 ships 3.12) | required by the app |
| about 1 GB of free RAM and 1 GB of free disk | the app is tiny; this is only for the install |
| you can use `sudo` | needed only to install OS packages (not to run the app) |

These came from earlier messages and **have not been checked by the author of this package**. Verify them yourself, in 10 seconds:

```bash
cd hospital-soc
bash scripts/check_env.sh
```

It prints the OS, architecture, RAM, disk, Python version, SQLite version, whether `venv`/Docker/Podman exist and
whether port 8000 is free. If something differs from the table above, use the matching command in the
**Troubleshooting** section.

---------------------------------------------------------------------------------------------------

## 2. Quick start (no Docker) - recommended

### 2.1 Copy the ZIP to the server and unpack it
From your own computer (replace `USER` and `SERVER`):
```bash
scp hospital-soc.zip USER@SERVER:~
ssh USER@SERVER
```
On the server:
```bash
sudo apt update && sudo apt install -y unzip python3 python3-venv python3-pip curl   # Ubuntu / Debian
# RHEL / Rocky / Alma:  sudo dnf install -y unzip python3 python3-pip curl
# SUSE:                 sudo zypper install -y unzip python3 python3-pip curl
unzip hospital-soc.zip
cd hospital-soc
bash scripts/check_env.sh
```

### 2.2 Install (creates a virtual environment, installs packages, writes `.env` with random tokens)
```bash
bash scripts/setup.sh
```
If `pip` cannot install a package (it can need to build one on s390x), use the OS packages instead:
```bash
sudo apt install -y python3-fastapi python3-uvicorn python3-pydantic
rm -rf .venv && bash scripts/setup.sh --system-site-packages
```

### 2.3 Start, check, and load demo data
```bash
bash scripts/start.sh            # starts in the background on 127.0.0.1:8000
bash scripts/status.sh           # shows PID and health
bash scripts/smoke_test.sh       # optional end-to-end check (also generates demo data)
```

### 2.4 Open the dashboard
The app listens on **localhost only** (safe default). From **your own computer** open an SSH tunnel and browse locally:
```bash
ssh -L 8000:localhost:8000 USER@SERVER
```
Then open **http://localhost:8000** and sign in with a token from the server:
```bash
grep SOC_ANALYST_TOKEN .env      # analyst: full access
grep SOC_VIEWER_TOKEN  .env      # viewer: read-only
```
Click **Generate simulated data** on the Overview page (or run `.venv/bin/python -m soc.cli seed`).

### 2.5 Stop, restart, logs
```bash
bash scripts/stop.sh             # graceful stop (forces after 10 s)
bash scripts/restart.sh          # stop + start (do this after editing .env)
tail -f logs/soc.log             # live log; Ctrl+C leaves the app running
```

### 2.6 Run the tests
```bash
bash scripts/test.sh
# to include the HTTP API tests too:
.venv/bin/python -m pip install -r requirements-dev.txt && bash scripts/test.sh
```

### 2.7 Optional: start automatically at boot (systemd)
```bash
bash scripts/stop.sh
sed -e "s|__USER__|$USER|g" -e "s|__DIR__|$PWD|g" deploy/hospital-soc.service | sudo tee /etc/systemd/system/hospital-soc.service
sudo systemctl daemon-reload && sudo systemctl enable --now hospital-soc
systemctl status hospital-soc          # logs: journalctl -u hospital-soc -f
sudo systemctl stop hospital-soc       # stop;  sudo systemctl restart hospital-soc  # restart
```

---------------------------------------------------------------------------------------------------

## 3. Docker / Podman (optional)

The official `python:3.12-slim` image is normally published for `linux/s390x`, so it should build natively on LinuxONE (not verified by the author).
Check first: `docker manifest inspect python:3.12-slim | grep -i s390x` (should print a line).

```bash
# 1) create .env with random tokens (needs python3 on the host)
python3 -m soc.cli init-env
#    ...or without python:  cp .env.example .env && sed -i "s|CHANGE_ME_run_scripts_setup_sh|$(openssl rand -hex 24)|" .env

# 2) build and run (container listens on 127.0.0.1:8000 of the host)
docker compose up -d --build
docker compose ps
docker compose logs -f             # Ctrl+C to leave
```
Stop / restart / remove:
```bash
docker compose stop                # stop, keep data
docker compose start               # start again
docker compose restart             # after editing .env
docker compose down                # remove container (data volume 'soc-data' is kept)
docker compose down -v             # ALSO deletes the database volume
```
Podman without compose:
```bash
podman build -t hospital-soc:1.0.0 .
podman run -d --name hospital-soc --env-file .env -p 127.0.0.1:8000:8000 \
  -e SOC_HOST=0.0.0.0 -e SOC_DB_PATH=/app/data/soc.db -e SOC_ASSETS_PATH=/app/assets/assets.csv \
  -v soc-data:/app/data:Z hospital-soc:1.0.0
podman stop hospital-soc ; podman start hospital-soc ; podman logs -f hospital-soc
```
Then use the same SSH tunnel as in 2.4. Load demo data from the dashboard, or:
`docker compose exec soc python -m soc.cli seed`.

---------------------------------------------------------------------------------------------------

## 4. Using the dashboard

| Screen | What you can do |
|---|---|
| **Overview** | KPIs (open alerts, critical, average score), alerts by severity / attack type / status, most affected systems, 24-hour activity chart. Buttons: *Generate simulated data*, *Re-run detection*, *Reset data* (asks for confirmation). Click any bar or system to jump to the matching alerts. |
| **Alerts** | Filter by status, attack type, severity, minimum score, system; free-text search; sort; export CSV. Click a row to open the **alert drawer**. |
| **Alert drawer** | Plain-English explanation, *why it matters*, confidence, **investigate / triage / contain / escalate** steps, the **5-factor score breakdown**, detection evidence, related detections, the **original log lines** (with raw JSON), **status control**, **analyst notes**, *Export these logs*, *Regenerate explanation*. |
| **Logs** | Search any text in raw logs; filter by source, event type, system, scenario label, user, IP, date range; paginate; export CSV or JSONL. |
| **Assets** | The simulated inventory (criticality 1-5, patient-care flag) with open-alert counts. |
| **Audit trail** | Every status change, note, export, generation and reset (analyst only). |

Roles: **analyst** can change status, add notes, generate/reset data; **viewer** is read-only (buttons are disabled and the server refuses writes).

Incident statuses: `new`, `investigating`, `contained`, `resolved`, `false_positive`. "Contained" is a label you set after
*people* have contained the issue; the application itself never contains anything.

---------------------------------------------------------------------------------------------------

## 5. Configuration (`.env`)

`scripts/setup.sh` creates `.env` from `.env.example`. After any change run `bash scripts/restart.sh`.

| Setting | Default | Meaning |
|---|---|---|
| `SOC_ANALYST_TOKEN` | *(random)* | **Required**, min. 16 chars. Full access. |
| `SOC_VIEWER_TOKEN` | *(random)* | Optional read-only token. Empty disables the viewer role. |
| `SOC_HOST` / `SOC_PORT` | `127.0.0.1` / `8000` | Keep `127.0.0.1` and use an SSH tunnel. |
| `SOC_DB_PATH` | `data/soc.db` | SQLite file. Back it up by copying it while the app is stopped. |
| `SOC_ASSETS_PATH` | `data/assets.csv` | Asset inventory (edit to match your simulated hospital). |
| `SOC_UTC_OFFSET_HOURS` | `0` | Hospital local time offset, used by the *after-hours* rules. Regenerate data after changing it. |
| `SOC_AI_PROVIDER` | `none` | `none` (offline) or `anthropic`. |
| `SOC_AI_API_KEY` / `SOC_AI_MODEL` / `SOC_AI_TIMEOUT` | *(empty)* / `claude-sonnet-5-5` / `20` | Used only when the provider is `anthropic`. |

### Optional AI explanations
By default everything is **offline**: explanations come from built-in templates. To let an external AI rewrite them, set
`SOC_AI_PROVIDER=anthropic` and `SOC_AI_API_KEY=...`, restart, then press **Regenerate with AI** in an alert.
Only the alert's summary (rule, score factors, evidence sentences, asset name/type) is sent - never raw log lines. If the
API is unreachable, the key is wrong, or the answer is malformed, the built-in explanation is shown automatically and a notice says so.
Keep AI **off** if you ever adapt this to non-simulated data unless your organisation has approved it. Check the model name against your account.

---------------------------------------------------------------------------------------------------

## 6. How detection and scoring work

**Detection** is 19 deterministic rules (no machine learning, no randomness) over the stored logs. Thresholds live in `soc/detection.py` (`DetectionConfig`).

| Rule | Detects | Default trigger |
|---|---|---|
| BF-001 | Repeated failed logins | 8+ failures from one address to one system in 5 min |
| BF-002 | Password spraying | 6+ different accounts failing from one address in 10 min |
| BF-003 | Success after failures | 5+ failures then a success (same user and address) within 10 min |
| EHR-001 | Bulk record access | 20+ patient records in 10 min with no care relationship |
| EHR-002 | After-hours access | 3+ no-care-relationship accesses within 1 h outside 07:00-19:00 |
| EHR-003 | VIP record access | any VIP record without a care relationship |
| MAL-001 | Antivirus not contained | `detected_only` / `quarantine_failed`, or 3+ detections in 1 h |
| MAL-002 | Encoded PowerShell | `-enc` / `-EncodedCommand` (higher confidence from Office parents) |
| MAL-003 | Known-bad connection | destination on the (simulated) indicator list |
| RAN-001 | Mass encryption | 200+ files renamed with a ransomware extension within 5-minute gaps |
| RAN-002 | Recovery tampering | shadow copies deleted or backup service stopped |
| RAN-003 | Ransom note | ransom-note file created |
| PRIV-001 | Admin-group change | not an approved admin, self-added, or after hours |
| PRIV-002 | Service-account logon | interactive logon by a service account |
| PRIV-003 | Audit log cleared | Security log cleared |
| DEV-001 | Device to internet | medical device talking to a non-private address |
| DEV-002 | Remote admin to device | RDP/SSH/Telnet/SMB/VNC from a host not on the allow-list |
| DEV-003 | Device port scan | 15+ distinct ports in 2 min |
| DEV-004 | Firmware change | outside a maintenance window |

**Risk score 1-10** = rule severity (0-4) + evidence strength (0-1.5) + corroborating detections nearby (0-1.5) +
asset criticality (0-1.5) + hospital impact (0-1.5), rounded and clamped to 1-10. Every component, with its reason, is shown
in the alert drawer. Labels: 1-3 low, 4-5 medium, 6-7 high, 8-10 critical. *Confidence* shows how far the logs exceed the rule threshold.
Re-running detection never duplicates alerts and never changes status or notes.

---------------------------------------------------------------------------------------------------

## 7. Command-line helpers

```bash
.venv/bin/python -m soc.cli seed                # generate + load + detect (wipes existing data; --keep to add)
.venv/bin/python -m soc.cli generate --out data/my_logs.jsonl --seed 7
.venv/bin/python -m soc.cli load data/sample_logs.jsonl     # load a JSONL file of SIMULATED logs
.venv/bin/python -m soc.cli detect              # re-run detection
.venv/bin/python -m soc.cli stats
.venv/bin/python -m soc.cli gen-token           # print a strong random token
```
`data/sample_logs.jsonl` is a ready-made sample (426 simulated logs, seed 42, 2026-10-16).

## 8. API summary

All `/api/*` routes except `/api/health` need `Authorization: Bearer <token>`. (Interactive API docs are disabled on purpose.)

| Method and path | Role | Purpose |
|---|---|---|
| `GET /api/health` | none | liveness check |
| `GET /api/me`, `/api/config`, `/api/options`, `/api/stats`, `/api/assets` | any | session info, settings, filter values, KPIs, inventory |
| `GET /api/alerts`, `GET /api/alerts/{id}` | any | list (filters: `q status category severity asset min_score start end sort limit offset`) / full detail |
| `GET /api/logs` | any | search (filters: `q source asset event_type username src_ip scenario start end alert_id limit offset`) |
| `POST /api/alerts/{id}/status` `{"status": ...}` | analyst | change incident status |
| `POST /api/alerts/{id}/notes` `{"text": ...}` | analyst | add note (max 2000 chars) |
| `POST /api/alerts/{id}/explain` | analyst | regenerate explanation (AI if enabled, else offline) |
| `POST /api/simulate`, `/api/detect`, `/api/reset` | analyst | generate data, re-run rules, delete all data (`{"confirm": true}`) |
| `GET /api/audit` | analyst | audit trail |
| `GET /api/export/logs.csv`, `logs.jsonl`, `alerts.csv`, `contract.csv` | any | exports (same filters as the lists) |

Example:
```bash
TOKEN=$(grep ^SOC_ANALYST_TOKEN .env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:8000/api/alerts?min_score=8&limit=3"
```

---------------------------------------------------------------------------------------------------

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `python3 -m venv` fails / "ensurepip is not available" | venv package missing | `sudo apt install -y python3-venv` (RHEL: `sudo dnf install python3`) and re-run `scripts/setup.sh` |
| `pip install` fails building `pydantic-core` or similar | no s390x wheel and no compiler/Rust | Use OS packages: `sudo apt install -y python3-fastapi python3-uvicorn python3-pydantic`, then `rm -rf .venv && bash scripts/setup.sh --system-site-packages`. Last resort (pure-Python versions, not verified on s390x by the author): `.venv/bin/pip install "fastapi==0.99.1" "pydantic<2" "uvicorn"` |
| `Configuration error: SOC_ANALYST_TOKEN ...` | `.env` missing or token is a placeholder | `python3 -m soc.cli init-env` (or edit `.env`; min. 16 chars) |
| `start.sh` says FAILED to start | see the last log lines it prints | `tail -n 50 logs/soc.log`; common: port in use, bad `.env`, packages missing |
| `Address already in use` | something already on port 8000 | `ss -ltnp \| grep :8000`; stop it, or set `SOC_PORT=8010` in `.env` and restart |
| Browser cannot connect | tunnel not open, or app not running | keep the `ssh -L 8000:localhost:8000 ...` window open; `bash scripts/status.sh` |
| Login says token not accepted | typo, trailing space, or old `.env` | copy it again with `grep SOC_ANALYST_TOKEN .env`; after editing `.env` run `scripts/restart.sh` |
| Dashboard says "No data yet" | database is empty | **Generate simulated data**, or `.venv/bin/python -m soc.cli seed` |
| Expected after-hours alerts missing | wrong time zone offset | set `SOC_UTC_OFFSET_HOURS`, restart, regenerate data |
| `database is locked` | two copies of the app share one DB file | `bash scripts/status.sh`; stop duplicates (`docker compose ps`, `systemctl status hospital-soc`) |
| `PermissionError` on `data/` | folder owned by another user | `sudo chown -R "$USER": data run logs` |
| AI notice "External AI unavailable" | no outbound internet, wrong key, or wrong model name | harmless (offline text is shown); check `SOC_AI_*` settings and firewall |
| Docker: "no matching manifest for linux/s390x" | base image not available for s390x | use the non-Docker route (section 2) |
| `docker compose` not found | old Docker | `docker-compose up -d --build` or install the compose plugin |
| Tests: 7 skipped | FastAPI/httpx test deps not installed | `.venv/bin/python -m pip install -r requirements-dev.txt` |

Still stuck? Run `bash scripts/check_env.sh` and `tail -n 50 logs/soc.log` and read them top to bottom.

---------------------------------------------------------------------------------------------------

## 10. Security notes and honest limitations

* **Simulated only.** Real logs are rejected by design (`simulated: true` is mandatory; patient IDs must look like `SIM-PT-12345`). Do not connect it to real systems.
* **Read-only.** There is no code path that changes a hospital system. "Block", "isolate" and similar words appear only in advice text.
* **Authentication** is two shared bearer tokens (analyst, viewer) compared in constant time; there are no per-user accounts, no lockout/rate limiting and **no built-in TLS**. Keep the default localhost binding and use an SSH tunnel; if you must expose it, put a TLS reverse proxy with extra access controls in front.
* Hardening included: strict input validation, parameterised SQL, text-only rendering in the browser (hostile log text cannot run as script), a content-security policy, CSV formula-injection protection in exports, disabled API docs, non-root container with a read-only filesystem, systemd sandboxing options.
* **Detection is rule-based.** It only finds what the rules describe and its thresholds were tuned on synthetic data; it has **not** been validated on real hospital traffic and will have false positives and false negatives there. MITRE ATT&CK IDs are indicative.
* **Scale:** a single SQLite file and an in-memory detection pass (capped at 200,000 logs) - fine for demos and prototypes, not for production volumes.
* **AI** (optional) only rewrites text; scores and detections never depend on it. Treat AI text as advisory.
* Back up by stopping the app and copying `data/soc.db`.

## 11. Relationship to the team's earlier files

* `data/assets.csv` is the team's `shared/assets.csv` (columns `asset, criticality, simulated` kept) extended with type, department, subnet, patient-care and PHI flags and 6 more systems (14 total).
* `GET /api/export/contract.csv` emits alerts in the team's 9-column contract
  (`timestamp, asset, criticality, src_ip_hashed, network_score, anomaly_score, threat_flag, risk_score, recommended_action`).
  The mapping is indicative because this SOC scores 1-10 (see `soc/contract.py`).
* Hanan's UNSW-NB15 Snap ML model is **not** used by the detection engine: it scores UNSW-NB15 network-flow statistics, while these
  logs are security events (logins, EHR access, endpoint and device events). It could be added later as an extra detector that feeds `network_score`.

## 12. Project layout

```
hospital-soc/
  README.md  requirements.txt  requirements-dev.txt  .env.example  Dockerfile  docker-compose.yml  pytest.ini
  soc/            application (config, assets, generator, detection, scoring, engine, explain, db, service, contract, main, cli)
  soc/static/     index.html  style.css  app.js   (the dashboard)
  data/           assets.csv (simulated inventory)  sample_logs.jsonl (simulated sample data)
  scripts/        setup.sh start.sh stop.sh restart.sh status.sh test.sh smoke_test.sh check_env.sh
  deploy/         hospital-soc.service (systemd template)
  tests/          unit, detection, scoring, explanation, service/export, config, front-end contract and API tests
```
