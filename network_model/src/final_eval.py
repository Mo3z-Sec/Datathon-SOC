import joblib
import numpy as np, pandas as pd
from snapml import RandomForestClassifier as SnapRF
from sklearn.preprocessing import OrdinalEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

THRESHOLD = 0.8   # chosen on validation: first threshold with val FPR < 2%

train = pd.read_csv("unsw_train.csv", keep_default_na=False)
test = pd.read_csv("unsw_test.csv", keep_default_na=False)
cat_cols = ["proto", "service", "state"]

X_full = train.drop(columns=["label", "attack_cat"])
X_test = test.drop(columns=["label", "attack_cat"]).copy()
y_full, y_test = train["label"], test["label"]
cat_full, cat_test = train["attack_cat"], test["attack_cat"]

X_train, X_val, y_train, y_val = train_test_split(
    X_full, y_full, test_size=0.2, stratify=cat_full, random_state=42)
X_train, X_val = X_train.copy(), X_val.copy()

enc = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
enc.fit(X_train[cat_cols])
for part in (X_train, X_val, X_test):
    part[cat_cols] = enc.transform(part[cat_cols])

group_map = {"Normal": "Normal", "DoS": "DoS/DDoS", "Reconnaissance": "Port scan/Recon",
             "Backdoor": "Malware-like", "Shellcode": "Malware-like", "Worms": "Malware-like",
             "Generic": "Generic", "Exploits": "Exploits", "Fuzzers": "Fuzzers", "Analysis": "Analysis"}
group_test = cat_test.map(group_map)

f32 = lambda d: d.values.astype(np.float32)
model = SnapRF(n_estimators=100, n_jobs=3, random_state=42)
model.fit(f32(X_train), y_train)

def report(name, y, proba):
    pred = (proba >= THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    print(f"{name}: acc {accuracy_score(y, pred):.4f} prec {precision_score(y, pred):.4f} "
          f"rec {recall_score(y, pred):.4f} fpr {fp/(fp+tn):.4f}")
    print(f"   confusion: TN={tn} FP={fp} FN={fn} TP={tp}")
    return pred

print(f"FINAL MODEL: IBM Snap ML RandomForest, threshold {THRESHOLD}")
report("VALIDATION", y_val, model.predict_proba(f32(X_val))[:, 1])
pt = model.predict_proba(f32(X_test))[:, 1]
pred = report("TEST      ", y_test, pt)

df = pd.DataFrame({"group": group_test.values, "flagged": pred})
print("\nPer group on TEST:")
print("(attack groups: share detected; Normal: share wrongly flagged = false alarm rate)")
print(df.groupby("group")["flagged"].agg(share_flagged="mean", rows="count").round(3))

bundle = dict(model=model, encoder=enc, features=list(X_train.columns),
              cat_cols=cat_cols, threshold=THRESHOLD)
joblib.dump(bundle, "cybershield_network_model.joblib")
print("\nsaved cybershield_network_model.joblib")

# Handoff self-test: reload exactly the way Jason will use it
from network_detector import NetworkDetector
det = NetworkDetector("cybershield_network_model.joblib")
out = det.predict(test)
same = (out["is_attack"].values == pred).all()
print("handoff test (reloaded model reproduces predictions):", "PASS" if same else "FAIL")
print(out.head(3))