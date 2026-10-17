import pandas as pd
from network_detector import NetworkDetector

print("Loading model and building test data...")
det = NetworkDetector("cybershield_network_model.joblib")

# Create a dummy row with all required features set to 0 or default string
df_dummy = pd.DataFrame(columns=det.features)
df_dummy.loc[0] = 0  # Fill with zeros for numeric features

# Fill categorical columns with a safe default string (like 'tcp')
for col in det.cat_cols:
    df_dummy[col] = 'tcp'

df_dummy.to_csv("test_traffic.csv", index=False)
print("SUCCESS: 'test_traffic.csv' created successfully!")
