# Isolation Forest - Benchmark Evaluation

**Dataset file:** `Tuesday-WorkingHours.pcap_ISCX.csv`  
**Evaluated:** 24 September 2026, 16:21  
**Flows analysed:** 200,000 · **Features used:** 68  
**Model:** IsolationForest(n_estimators=200, contamination=0.031, random_state=42) - unsupervised

## Class distribution in the dataset

| Label | Flows |
|---|---|
| BENIGN | 193,753 |
| FTP-Patator | 3,528 |
| SSH-Patator | 2,719 |

## Results

| Metric | Score |
|---|---|
| Accuracy | 0.9375 |
| Precision | 0.0000 |
| Recall | 0.0000 |
| F1 score | 0.0000 |
| ROC-AUC | 0.6713 |

## Confusion matrix

| | Predicted benign | Predicted attack |
|---|---|---|
| **Actually benign** | 187,506 (true negative) | 6,247 (false positive) |
| **Actually attack** | 6,247 (false negative) | 0 (true positive) |

## How to read these numbers

- **Precision 0.00** - of every flow the model flagged, 0% really were attacks. Low precision means analyst time wasted on false alarms (alert fatigue).
- **Recall 0.00** - of all real attacks present, the model caught 0%. Low recall means attacks slipping through.
- **ROC-AUC 0.67** - how well the anomaly score separates attacks from benign traffic overall (0.5 = random guessing, 1.0 = perfect).

**Context:** this is an *unsupervised* model that was never shown a single attack label during training. Supervised models such as XGBoost typically score higher on this benchmark, but require labelled data that real deployments do not have. This is exactly the trade-off our CO1 proposal identified, and it is why SentinelAI pairs the model with a deterministic rule engine rather than relying on it alone.
