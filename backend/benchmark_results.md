# Isolation Forest - Benchmark Evaluation

**Dataset file:** `sample_cicids2017_tuesday.csv`  
**Evaluated:** 16 August 2026, 01:12  
**Flows analysed:** 1,000 · **Features used:** 18  
**Model:** IsolationForest(n_estimators=200, contamination=0.150, random_state=42) - unsupervised

## Class distribution in the dataset

| Label | Flows |
|---|---|
| BENIGN | 850 |
| FTP-Patator | 86 |
| SSH-Patator | 64 |

## Results

| Metric | Score |
|---|---|
| Accuracy | 0.8460 |
| Precision | 0.4867 |
| Recall | 0.4867 |
| F1 score | 0.4867 |
| ROC-AUC | 0.8967 |

## Confusion matrix

| | Predicted benign | Predicted attack |
|---|---|---|
| **Actually benign** | 773 (true negative) | 77 (false positive) |
| **Actually attack** | 77 (false negative) | 73 (true positive) |

## How to read these numbers

- **Precision 0.49** - of every flow the model flagged, 49% really were attacks. Low precision means analyst time wasted on false alarms (alert fatigue).
- **Recall 0.49** - of all real attacks present, the model caught 49%. Low recall means attacks slipping through.
- **ROC-AUC 0.90** - how well the anomaly score separates attacks from benign traffic overall (0.5 = random guessing, 1.0 = perfect).

**Context:** this is an *unsupervised* model that was never shown a single attack label during training. Supervised models such as XGBoost typically score higher on this benchmark, but require labelled data that real deployments do not have. This is exactly the trade-off our CO1 proposal identified, and it is why SentinelAI pairs the model with a deterministic rule engine rather than relying on it alone.
