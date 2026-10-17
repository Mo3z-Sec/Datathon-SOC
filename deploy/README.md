# deploy/

Owner: **Moe**

LinuxONE (`s390x`) packaging, containers, and the response simulation.

## Goals
- Containerize `engine/` + `dashboard/` so the system runs on IBM LinuxONE.
- Confirm Python libraries install on `s390x` (prefer Ubuntu apt packages over pip:
  `python3-pandas python3-sklearn python3-matplotlib python3-seaborn python3-requests`).
- Simulate the response action (quarantine the hashed source, keep clinical systems up).

## Notes
- Nour's data-side run script is at `../data_pipeline/run_on_linuxone.sh`.
- VM: Ubuntu 24.04 `s390x`, host `148.100.108.167`, shared by the team — coordinate
  so heavy jobs don't run at the same time.
