import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import numpy as np
from datetime import datetime
from engine.network_detector import NetworkDetector
from shared.schema import compute_risk_score, recommended_action, validate_alert_row

print("--- Generating CyberShield Engine Alerts ---")
det = NetworkDetector("engine/cybershield_network_model.joblib")

# Read test traffic from engine folder
df = pd.read_csv("engine/test_traffic.csv", keep_default_na=False)

# Run network detector predictions
results = det.predict(df, threshold=0.5)

# Build the final alerts DataFrame based on the contract
alerts = []
for idx, row in results.iterrows():
    network_score = float(row.get("risk_score", 0.0)) / 100.0
    anomaly_score = 0.0
    threat_flag = 0
    
    asset = str(row.get("asset", "Unknown-Asset"))
    criticality = str(row.get("criticality", "Medium"))
    
    risk = compute_risk_score(network_score, anomaly_score, threat_flag, criticality)
    action = recommended_action(risk)
    
    alert_row = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "asset": asset,
        "criticality": criticality,
        "src_ip_hashed": str(row.get("src_ip_hashed", "hash_default")),
        "network_score": round(network_score, 4),
        "anomaly_score": round(anomaly_score, 4),
        "threat_flag": int(threat_flag),
        "risk_score": round(risk, 2),
        "recommended_action": action
    }
    
    validate_alert_row(alert_row)
    alerts.append(alert_row)

alerts_df = pd.DataFrame(alerts)
alerts_df.to_csv("engine/alerts.csv", index=False)
print(f"Successfully generated {len(alerts_df)} rows and saved to engine/alerts.csv")
