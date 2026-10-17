# engine/

Owner: **Jason**

The real-time loop + risk fusion. This is the only place that writes
`risk_score` and `recommended_action`.

## Inputs
- `network_score` from `../models/` (Hanan)
- `anomaly_score` from `../models/` (Bardia)
- `threat_flag` from `../data_pipeline/threat_intel.py` -> `is_known_bad(url)`
- `asset` + `criticality` from `../data_pipeline/outputs/assets.csv` / the split CSVs

## Output
Write `engine/alerts.csv` with the exact columns from
[`../shared/CONTRACT.md`](../shared/CONTRACT.md). Use `../shared/schema.py`:

```python
from shared.schema import compute_risk_score, recommended_action
```

Hospital rule: `recommended_action` isolates, never shuts down clinical systems.
