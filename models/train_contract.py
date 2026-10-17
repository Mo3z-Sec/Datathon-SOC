import json, os, time, joblib
import numpy as np, pandas as pd
from snapml import RandomForestClassifier as SnapRF
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix, roc_auc_score

train = pd.read_csv("unsw_train.csv")
val = pd.read_csv("unsw_val.csv")
test = pd.read_csv("unsw_test.csv")

NOT_FEATURES = {"label_binary", "asset", "criticality", "attack_cat", "label"}
features = [c for c in train.columns if c not in NOT_FEATURES]
print("features:", len(features))
if os.path.exists("scaler_unsw.json"):
    cols = json.load(open("scaler_unsw.json"))["columns"]
    print("matches scaler_unsw.json columns:", cols == features)

f32 = lambda d: d[features].values.astype(np.float32)
Xtr, Xva, Xte = f32(train), f32(val), f32(test)
ytr, yva, yte = train["label_binary"].values, val["label_binary"].values, test["label_binary"].values
print("rows -> train", Xtr.shape, "val", Xva.shape, "test", Xte.shape)
print("attack share: train %.3f, test %.3f" % (ytr.mean(), yte.mean()))

model = SnapRF(n_estimators=100, n_jobs=3, random_state=42)
t = time.time(); model.fit(Xtr, ytr); print(f"train time {time.time()-t:.1f}s")
t = time.time(); pte = model.predict_proba(Xte)[:, 1]
print(f"inference {(time.time()-t)/len(Xte)*1000:.4f} ms/record")
pva = model.predict_proba(Xva)[:, 1]
print("test AUC: %.4f" % roc_auc_score(yte, pte))

def m(y, p, thr):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return accuracy_score(y, pred), precision_score(y, pred), recall_score(y, pred), fp / (fp + tn)

print("\nthr  | VAL fpr rec | TEST fpr rec prec acc")
chosen = 0.5
sweep = [0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
for thr in sweep:
    a, b = m(yva, pva, thr), m(yte, pte, thr)
    print(f"{thr:<5}| {a[3]:.3f} {a[2]:.3f} | {b[3]:.3f} {b[2]:.3f} {b[1]:.3f} {b[0]:.3f}")
for thr in sweep:
    if m(yva, pva, thr)[3] < 0.02:
        chosen = thr; break
acc, prec, rec, fpr = m(yte, pte, chosen)
print(f"\nreference threshold (first with val FPR < 2%): {chosen}")
print(f"TEST: acc {acc:.4f} prec {prec:.4f} rec {rec:.4f} fpr {fpr:.4f}")

if "attack_cat" in test.columns:
    flag = pd.DataFrame({"group": test["attack_cat"].values, "flagged": (pte >= chosen).astype(int)})
    print(flag.groupby("group")["flagged"].agg(share_flagged="mean", rows="count").round(3))
else:
    print("\n(no attack_cat column in these CSVs, so no per-attack breakdown)")

joblib.dump(dict(model=model, features=features, threshold=chosen, ref_test_acc=float(acc)), "model_unsw.pkl")
json.dump(features, open("model_features_unsw.json", "w"), indent=2)
print("saved model_unsw.pkl and model_features_unsw.json")