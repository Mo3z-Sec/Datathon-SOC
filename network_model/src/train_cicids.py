import time, joblib
import numpy as np, pandas as pd
from snapml import RandomForestClassifier as SnapRF
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

df = pd.read_csv("cicids_sample.csv")
grp = df.pop("Group")
y = (grp != "Normal").astype(int)
features = list(df.columns)
X = df.values.astype(np.float32)

Xtr, Xtmp, ytr, ytmp, gtr, gtmp = train_test_split(X, y, grp, test_size=0.4, stratify=grp, random_state=42)
Xva, Xte, yva, yte, gva, gte = train_test_split(Xtmp, ytmp, gtmp, test_size=0.5, stratify=gtmp, random_state=42)
print("train", Xtr.shape, "val", Xva.shape, "test", Xte.shape)

model = SnapRF(n_estimators=100, n_jobs=3, random_state=42)
t = time.time(); model.fit(Xtr, ytr); print(f"train time {time.time()-t:.1f}s")
t = time.time(); pte = model.predict_proba(Xte)[:, 1]
print(f"inference {(time.time()-t)/len(Xte)*1000:.4f} ms/record")
pva = model.predict_proba(Xva)[:, 1]

def m(y, p, thr):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return accuracy_score(y, pred), precision_score(y, pred), recall_score(y, pred), fp / (fp + tn)

print("\nthr | VAL fpr rec | TEST fpr rec prec acc")
chosen = 0.5
for thr in [0.5, 0.6, 0.7, 0.8, 0.9]:
    a, b = m(yva, pva, thr), m(yte, pte, thr)
    print(f"{thr:<4}| {a[3]:.4f} {a[2]:.4f} | {b[3]:.4f} {b[2]:.4f} {b[1]:.4f} {b[0]:.4f}")
for thr in [0.5, 0.6, 0.7, 0.8, 0.9]:
    if m(yva, pva, thr)[3] < 0.02:
        chosen = thr; break
print("\nchosen threshold (first with val FPR < 2%):", chosen)

acc, prec, rec, fpr = m(yte, pte, chosen)
print(f"TEST: acc {acc:.4f} prec {prec:.4f} rec {rec:.4f} fpr {fpr:.4f}")
flag = pd.DataFrame({"group": gte.values, "flagged": (pte >= chosen).astype(int)})
print("\nPer group on TEST (attacks: share detected; Normal: false alarm rate):")
print(flag.groupby("group")["flagged"].agg(share_flagged="mean", rows="count").round(4))

joblib.dump(dict(model=model, features=features, threshold=chosen), "cicids_model.joblib")
print("\nsaved cicids_model.joblib")