import glob
import numpy as np, pandas as pd

files = sorted(glob.glob("data/cicids/*.csv"))
print("files found:", len(files))
df = pd.concat([pd.read_csv(f, low_memory=False) for f in files], ignore_index=True)
df.columns = df.columns.str.strip()
df["Label"] = df["Label"].astype(str).str.strip()
print("raw rows:", len(df))

def group(l):
    if l == "BENIGN": return "Normal"
    if l in ("FTP-Patator", "SSH-Patator"): return "Brute force"
    if l.startswith("DoS") or l == "DDoS": return "DoS/DDoS"
    if l == "PortScan": return "Port scan/Recon"
    if l == "Bot": return "Malware-like"
    if l.startswith("Web Attack"): return "Web attack"
    return "Other"

df["Group"] = df["Label"].map(group)
df = df.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()
print("after cleaning:", len(df))
print(df["Group"].value_counts())

# cap each group so the file stays small enough for the VM
parts = []
for g, d in df.groupby("Group"):
    cap = 200000 if g == "Normal" else 60000
    parts.append(d.sample(min(len(d), cap), random_state=42))
out = pd.concat(parts).sample(frac=1, random_state=42)
out.drop(columns=["Label"]).to_csv("data/cicids_sample.csv", index=False)
print("\nsaved sample:", out.shape)
print(out["Group"].value_counts())