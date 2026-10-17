import pandas as pd
from network_detector import NetworkDetector

print("--- Running CyberShield Inference Test ---")
det = NetworkDetector("cybershield_network_model.joblib")

# Read using Hanan's required rule
df = pd.read_csv("test_traffic.csv", keep_default_na=False)

# Get predictions
results = det.predict(df, threshold=0.8)

print("Analysis Results:")
print(results)
