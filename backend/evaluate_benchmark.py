# evaluate_benchmark.py
# =============================================================================
# BENCHMARK EVALUATION OF THE ISOLATION FOREST MODEL
#
# WHY THIS SCRIPT EXISTS:
#   Our live system (ai_engine.py) runs Isolation Forest on UNLABELLED logs, so
#   we can never tell from it whether the model is actually any good. Benchmark
#   datasets such as CIC-IDS2017 come with a ground-truth "Label" column, which
#   lets us MEASURE the model properly: precision, recall, F1 and a confusion
#   matrix. Those numbers are what we report in our CO3 evaluation.
#
# WHAT IT DOES:
#   1. Loads a benchmark CSV (CIC-IDS2017 / CIC-DDoS2019 / UNSW-NB15 style).
#   2. Cleans it - real CIC files have leading spaces in column names, infinite
#      values in the "Flow Bytes/s" column, and missing values.
#   3. Trains an unsupervised Isolation Forest on the numeric flow features.
#      IMPORTANT: the labels are NEVER shown to the model. They are used only
#      afterwards, to score how well it did.
#   4. Prints and saves a full evaluation report.
#
# HOW TO RUN:
#   pip install pandas scikit-learn
#   python evaluate_benchmark.py sample_cicids2017_tuesday.csv
#   python evaluate_benchmark.py "data/Tuesday-WorkingHours.pcap_ISCX.csv"
# =============================================================================

import sys
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)

# Columns that identify a flow rather than describe its behaviour. They must be
# dropped or the model would "cheat" by memorising addresses instead of learning
# behaviour. (Not every dataset contains all of these.)
IDENTIFIER_COLUMNS = {
    "flow id", "source ip", "src ip", "destination ip", "dst ip",
    "timestamp", "source port", "src port", "protocol", "id",
    "attack_cat", "external ip", "similarhttp",
}

MAX_ROWS = 200_000   # cap for speed; real CIC files can have millions of rows


def load_and_clean(path: str):
    """Load a benchmark CSV and return (features, true_labels, label_names)."""
    print(f"Loading {path} ...")
    df = pd.read_csv(path, low_memory=False)
    print(f"  raw shape: {df.shape[0]:,} rows x {df.shape[1]} columns")

    # --- 1. Fix messy headers -------------------------------------------------
    # Real CIC-IDS2017 files ship with leading spaces, e.g. " Flow Duration".
    df.columns = [str(c).strip() for c in df.columns]

    # --- 2. Find the label column --------------------------------------------
    label_col = None
    for candidate in ("Label", "label", "Attack", "class"):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise SystemExit("ERROR: no 'Label' column found - is this a benchmark file?")

    # --- 3. Sample if the file is very large ---------------------------------
    if len(df) > MAX_ROWS:
        df = df.sample(n=MAX_ROWS, random_state=42)
        print(f"  sampled down to {MAX_ROWS:,} rows for speed")

    # --- 4. Build the ground truth -------------------------------------------
    # Anything not labelled BENIGN/Normal is an attack (1); benign is 0.
    raw_labels = df[label_col].astype(str).str.strip()
    y_true = (~raw_labels.str.upper().isin(["BENIGN", "NORMAL", "0"])).astype(int)
    label_names = raw_labels.value_counts()

    # --- 5. Select the feature columns ---------------------------------------
    X = df.drop(columns=[label_col])
    X = X.drop(columns=[c for c in X.columns if c.strip().lower() in IDENTIFIER_COLUMNS],
               errors="ignore")
    X = X.select_dtypes(include=[np.number])          # numeric features only

    # --- 6. Clean the values --------------------------------------------------
    # "Flow Bytes/s" often contains inf when duration is 0; models cannot use inf.
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    X = X.loc[:, X.std() > 0]                          # drop constant columns

    print(f"  usable features: {X.shape[1]}")
    print(f"  ground truth: {int(y_true.sum()):,} attacks / {len(y_true):,} flows "
          f"({y_true.mean() * 100:.1f}% attack)")
    return X.values, y_true.values, label_names


def evaluate(X, y_true):
    """Train Isolation Forest (unsupervised) and score it against the truth."""
    contamination = float(np.clip(y_true.mean(), 0.001, 0.5))
    print(f"\nTraining Isolation Forest (contamination={contamination:.3f}) ...")

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,   # expected proportion of anomalies
        random_state=42,
        n_jobs=-1,
    )
    # NOTE: only X is passed. The model never sees y_true.
    model.fit(X)

    # predict(): -1 = anomaly, 1 = normal. Convert to 1 = attack, 0 = benign.
    y_pred = (model.predict(X) == -1).astype(int)

    # Continuous anomaly score, used for ROC-AUC (higher = more anomalous).
    scores = -model.score_samples(X)

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, scores),
        "confusion": confusion_matrix(y_true, y_pred),
        "contamination": contamination,
    }


def report(path, results, label_names, n_features, n_rows):
    """Print the evaluation report and save it to a Markdown file."""
    tn, fp, fn, tp = results["confusion"].ravel()

    lines = []
    add = lines.append
    add("# Isolation Forest - Benchmark Evaluation")
    add("")
    add(f"**Dataset file:** `{path}`  ")
    add(f"**Evaluated:** {datetime.now().strftime('%d %B %Y, %H:%M')}  ")
    add(f"**Flows analysed:** {n_rows:,} · **Features used:** {n_features}  ")
    add(f"**Model:** IsolationForest(n_estimators=200, "
        f"contamination={results['contamination']:.3f}, random_state=42) - unsupervised")
    add("")
    add("## Class distribution in the dataset")
    add("")
    add("| Label | Flows |")
    add("|---|---|")
    for name, count in label_names.items():
        add(f"| {name} | {count:,} |")
    add("")
    add("## Results")
    add("")
    add("| Metric | Score |")
    add("|---|---|")
    add(f"| Accuracy | {results['accuracy']:.4f} |")
    add(f"| Precision | {results['precision']:.4f} |")
    add(f"| Recall | {results['recall']:.4f} |")
    add(f"| F1 score | {results['f1']:.4f} |")
    add(f"| ROC-AUC | {results['roc_auc']:.4f} |")
    add("")
    add("## Confusion matrix")
    add("")
    add("| | Predicted benign | Predicted attack |")
    add("|---|---|---|")
    add(f"| **Actually benign** | {tn:,} (true negative) | {fp:,} (false positive) |")
    add(f"| **Actually attack** | {fn:,} (false negative) | {tp:,} (true positive) |")
    add("")
    add("## How to read these numbers")
    add("")
    add(f"- **Precision {results['precision']:.2f}** - of every flow the model flagged, "
        f"{results['precision'] * 100:.0f}% really were attacks. Low precision means analyst "
        "time wasted on false alarms (alert fatigue).")
    add(f"- **Recall {results['recall']:.2f}** - of all real attacks present, the model caught "
        f"{results['recall'] * 100:.0f}%. Low recall means attacks slipping through.")
    add(f"- **ROC-AUC {results['roc_auc']:.2f}** - how well the anomaly score separates attacks "
        "from benign traffic overall (0.5 = random guessing, 1.0 = perfect).")
    add("")
    add("**Context:** this is an *unsupervised* model that was never shown a single attack "
        "label during training. Supervised models such as XGBoost typically score higher on "
        "this benchmark, but require labelled data that real deployments do not have. This is "
        "exactly the trade-off our CO1 proposal identified, and it is why SentinelAI pairs the "
        "model with a deterministic rule engine rather than relying on it alone.")
    add("")

    text = "\n".join(lines)
    out = "benchmark_results.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)

    print("\n" + "=" * 62)
    print(f"  Accuracy : {results['accuracy']:.4f}")
    print(f"  Precision: {results['precision']:.4f}")
    print(f"  Recall   : {results['recall']:.4f}")
    print(f"  F1 score : {results['f1']:.4f}")
    print(f"  ROC-AUC  : {results['roc_auc']:.4f}")
    print("=" * 62)
    print(f"  TN={tn:,}  FP={fp:,}  FN={fn:,}  TP={tp:,}")
    print("=" * 62)
    print(f"\nFull report saved to: {out}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("Usage: python evaluate_benchmark.py <benchmark_file.csv>")
        raise SystemExit(1)

    path = sys.argv[1]
    X, y_true, label_names = load_and_clean(path)
    results = evaluate(X, y_true)
    report(path, results, label_names, X.shape[1], X.shape[0])


if __name__ == "__main__":
    main()
