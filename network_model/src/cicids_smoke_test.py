import pandas as pd
from cicids_detector import CicidsDetector

df = pd.read_csv("cicids_sample.csv")
g = df.pop("Group")
out = CicidsDetector("cicids_model.joblib").predict(df.head(3000))
print(out.head(3))
print(pd.crosstab(g.head(3000), out["is_attack"]))