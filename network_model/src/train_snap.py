import time, joblib
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier as SkRF
from snapml import RandomForestClassifier as SnapRF
from sklearn.preprocessing import OrdinalEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

train = pd.read_csv("unsw_train.csv", keep_default_na=False)
test = pd.read_csv("unsw_test.csv", keep_default_na=False)
cat_cols = ["proto", "service", "state"]

X_full = train.drop(columns=["label", "attack_cat"])
X_test = test.drop(columns=["label", "attack_cat"]).copy()
y_full, y_test = train["label"], test["label"]
cat_full, cat_test = train["attack_cat"], test["attack_cat"]

X_train, X_val, y_train, y_val, cat_train, cat_val = train_test_split(
    X_full, y_full, cat_full, test_size=0.2, stratify=cat_full, random_state=42)
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
Xtr, Xva, Xte = f32(X_train), f32(X_val), f32(X_test)
print("Rows -> train", Xtr.shape, "val", Xva.shape, "test", Xte.shape)

def metrics(y, proba, thr=0.5):
    pred = (proba >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return dict(acc=accuracy_score(y, pred), prec=precision_score(y, pred),
                rec=recall_score(y, pred), fpr=fp / (fp + tn))

def run(name, model):
    t = time.time(); model.fit(Xtr, y_train); fit_s = time.time() - t
    t = time.time(); pt = model.predict_proba(Xte)[:, 1]; ms = (time.time() - t) / len(Xte) * 1000
    pv = model.predict_proba(Xva)[:, 1]
    m = metrics(y_test, pt)
    print(f"\n=== {name} ===")
    print(f"train time {fit_s:.1f}s | inference {ms:.4f} ms/record")
    v = metrics(y_val, pv)
    print(f"VAL : acc {v['acc']:.4f} prec {v['prec']:.4f} rec {v['rec']:.4f} fpr {v['fpr']:.4f}")
    print(f"TEST: acc {m['acc']:.4f} prec {m['prec']:.4f} rec {m['rec']:.4f} fpr {m['fpr']:.4f}")
    return model, pv, pt

sk, _, _ = run("scikit-learn RandomForest", SkRF(n_estimators=100, n_jobs=3, random_state=42))
snap, pv, pt = run("IBM Snap ML RandomForest", SnapRF(n_estimators=100, n_jobs=3, random_state=42))

print("\nSnap ML per group on TEST (share classified correctly):")
df = pd.DataFrame({"group": group_test.values, "ok": ((pt >= 0.5).astype(int) == y_test.values)})
print(df.groupby("group")["ok"].agg(rate="mean", rows="count").round(3))

print("\nThreshold sweep (Snap ML): thr | VAL fpr rec | TEST fpr rec prec acc")
for thr in [0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]:
    a, b = metrics(y_val, pv, thr), metrics(y_test, pt, thr)
    print(f"{thr:<5} | {a['fpr']:.3f} {a['rec']:.3f} | {b['fpr']:.3f} {b['rec']:.3f} {b['prec']:.3f} {b['acc']:.3f}")

joblib.dump(enc, "encoder_vm.joblib")
try:
    joblib.dump(snap, "snap_rf_vm.joblib"); print("\nsaved snap_rf_vm.joblib")
except Exception as e:
    print("\ncould not pickle Snap model:", e)