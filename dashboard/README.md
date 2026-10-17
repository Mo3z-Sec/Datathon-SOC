# dashboard/

Owner: **Felix**

Streamlit front-end (the demo the judges see). It should **only read the alert
table** — never compute risk itself.

## Read from
- `../shared/sample_alerts.csv` (today, to build against)
- `../engine/alerts.csv` (once Jason's engine runs)

Columns are fixed by [`../shared/CONTRACT.md`](../shared/CONTRACT.md).

## Suggested views
- Live alert feed (newest first) with risk badge.
- Top assets at risk (group by `asset`, color by `criticality`).
- Risk distribution / timeline.
- One row's story: hashed source -> scores -> recommended action.

Run: `streamlit run dashboard/app.py`
