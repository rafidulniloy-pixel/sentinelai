import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, precision_score, recall_score

IDS = {"flow id","source ip","src ip","destination ip","dst ip","timestamp",
       "source port","src port","protocol","id","attack_cat","external ip","similarhttp"}

path = sys.argv[1] if len(sys.argv) > 1 else "Tuesday-WorkingHours.pcap_ISCX.csv"
df = pd.read_csv(path, low_memory=False)
df.columns = [str(c).strip() for c in df.columns]
if len(df) > 200_000:
    df = df.sample(n=200_000, random_state=42)

labels = df["Label"].astype(str).str.strip()
y = (~labels.str.upper().isin(["BENIGN", "NORMAL", "0"])).astype(int).values

X = df.drop(columns=["Label"])
X = X.drop(columns=[c for c in X.columns if c.strip().lower() in IDS], errors="ignore")
X = X.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan).fillna(0)
X = X.loc[:, X.std() > 0]
Xv = X.values
print(f"{len(df):,} flows | {Xv.shape[1]} features | {y.sum():,} attacks\n")

model = IsolationForest(n_estimators=200, contamination=float(y.mean()),
                        random_state=42, n_jobs=-1).fit(Xv)
scores = -model.score_samples(Xv)

print("=== 1. WHERE DO ATTACKS RANK? (100 = most anomalous) ===")
pct = 100.0 * scores.argsort().argsort() / (len(scores) - 1)
for name, m in [("BENIGN", y == 0), ("ATTACK", y == 1)]:
    print(f"  {name}  n={m.sum():>7,}  median={np.median(pct[m]):6.2f}  "
          f"mean={pct[m].mean():6.2f}  max={pct[m].max():6.2f}")
print(f"  ROC-AUC = {roc_auc_score(y, scores):.4f}\n")

print("=== 2. WHAT IF WE FLAG MORE THAN 3.1%? ===")
print(f"  {'flag top':>9} {'caught':>8} {'recall':>8} {'precision':>10}")
ranked = np.argsort(scores)[::-1]
for frac in [0.01, 0.031, 0.05, 0.10, 0.20, 0.30, 0.50]:
    k = int(len(scores) * frac)
    caught = int(y[ranked[:k]].sum())
    print(f"  {frac*100:8.1f}% {caught:8,} {caught/y.sum():8.3f} {caught/k:10.3f}")

print("\n=== 3. LABELS OF THE 2,000 MOST ANOMALOUS FLOWS ===")
for label, n in labels.iloc[ranked[:2000]].value_counts().items():
    print(f"  {label:22s} {n:>6,}")

print("\n=== 4. SANITY CHECK: CAN A SUPERVISED MODEL DO IT? ===")
Xtr, Xte, ytr, yte = train_test_split(Xv, y, test_size=0.3, random_state=42, stratify=y)
rf = RandomForestClassifier(n_estimators=60, random_state=42, n_jobs=-1).fit(Xtr, ytr)
pred = rf.predict(Xte)
print(f"  RandomForest  precision={precision_score(yte, pred):.4f}  "
      f"recall={recall_score(yte, pred):.4f}")