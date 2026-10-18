import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\PC\Documents\Datathon-SOC\network_model\results"
os.makedirs(OUT, exist_ok=True)

# ---- Chart 1: detection rate per attack type (numbers from the LinuxONE runs) ----
cicids = {"Brute force (FTP/SSH)": 99.89, "DoS / DDoS": 99.85, "Port scan": 100.0,
          "Web attacks": 98.13, "Malware-like (botnet)": 83.85}
unsw = {"Generic": 99.5, "Port scan / Recon": 97.3, "DoS / DDoS": 95.9, "Analysis": 95.1,
        "Exploits": 93.4, "Malware-like (backdoor, shellcode, worms)": 88.0, "Fuzzers": 45.6}

fig, axes = plt.subplots(1, 2, figsize=(13, 5))
for ax, data, title, fa in [
    (axes[0], cicids, "CIC-IDS2017 (threshold 0.5)", 0.10),
    (axes[1], unsw, "UNSW-NB15 (threshold 0.8)", 4.7),
]:
    names = list(data)[::-1]
    vals = [data[n] for n in names]
    bars = ax.barh(names, vals, color="#2f6db5")
    for b, v in zip(bars, vals):
        ax.text(v + 0.8, b.get_y() + b.get_height() / 2, f"{v + 1e-9:.1f}%", va="center", fontsize=9)
    ax.set_xlim(0, 112)
    ax.set_xlabel("Share of attack flows detected (%)")
    ax.set_title(f"{title}\nfalse alarms on normal traffic: {fa}%")
fig.suptitle("Detection rate per attack type (IBM Snap ML on LinuxONE, test sets)", fontsize=13)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "chart_1_per_attack_detection.png"), dpi=160)
plt.close(fig)

# ---- Chart 2: false alarms vs attacks caught, by threshold (contract model, test set) ----
thr = [0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
fpr = [38.5, 27.3, 20.2, 13.6, 6.7, 2.0, 0.7]
rec = [99.8, 98.7, 97.4, 95.0, 91.8, 87.1, 81.2]
fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(thr, rec, marker="o", color="#2f6db5", label="Attacks caught (recall)")
ax.plot(thr, fpr, marker="s", color="#c0392b", label="False alarms (false positive rate)")
ax.axvline(0.8, color="gray", linestyle="--")
ax.text(0.805, 55, "reference\nthreshold 0.8", fontsize=9, color="gray")
ax.annotate("6.7%", (0.8, 6.7), textcoords="offset points", xytext=(8, 8), color="#c0392b")
ax.annotate("91.8%", (0.8, 91.8), textcoords="offset points", xytext=(8, -14), color="#2f6db5")
ax.set_xlabel("Decision threshold")
ax.set_ylabel("%")
ax.set_ylim(0, 105)
ax.set_title("Cutting false alarms: threshold trade-off\n(UNSW-NB15, IBM Snap ML on LinuxONE, test set)")
ax.legend(loc="center left")
ax.grid(alpha=0.3)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "chart_2_threshold_tradeoff.png"), dpi=160)
plt.close(fig)

# ---- Chart 3: IBM Snap ML vs scikit-learn on the same IBM Z machine ----
fig, axes = plt.subplots(1, 2, figsize=(9, 4))
labels = ["scikit-learn", "IBM Snap ML"]
colors = ["#7f8c8d", "#2f6db5"]
for ax, vals, title, unit in [
    (axes[0], [6.7, 5.2], "Training time", "seconds"),
    (axes[1], [0.0028, 0.0019], "Inference per flow", "milliseconds"),
]:
    bars = ax.bar(labels, vals, color=colors)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v}", ha="center", va="bottom")
    ax.set_title(title)
    ax.set_ylabel(unit)
    ax.set_ylim(0, max(vals) * 1.25)
fig.suptitle("Random Forest on LinuxONE (s390x): Snap ML is faster, similar accuracy", fontsize=11)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "chart_3_snapml_vs_sklearn.png"), dpi=160)
plt.close(fig)

print("saved 3 charts in", OUT)