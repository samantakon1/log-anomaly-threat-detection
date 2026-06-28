# Synthetic Scenario Evaluation Summary

- Evaluation ID: `synthetic_eval_20260623_221514`
- Model version: `request_iforest_20260623_221511`
- Synthetic rows evaluated: 700
- Attack-like rows: 400
- Benign anomaly rows: 300

## Precision and Recall

| Ranking method | Metric | K | Value |
| --- | --- | ---: | ---: |
| anomaly_only | precision_at_k | 10 | 1.0000 |
| anomaly_only | precision_at_k | 20 | 1.0000 |
| anomaly_only | precision_at_k | 50 | 1.0000 |
| anomaly_only | precision_at_k | 100 | 1.0000 |
| anomaly_only | precision_at_k | 200 | 1.0000 |
| anomaly_only | precision_at_k | 300 | 1.0000 |
| anomaly_only | recall_at_k | 10 | 0.0250 |
| anomaly_only | recall_at_k | 20 | 0.0500 |
| anomaly_only | recall_at_k | 50 | 0.1250 |
| anomaly_only | recall_at_k | 100 | 0.2500 |
| anomaly_only | recall_at_k | 200 | 0.5000 |
| anomaly_only | recall_at_k | 300 | 0.7500 |
| anomaly_plus_threat_score | precision_at_k | 10 | 1.0000 |
| anomaly_plus_threat_score | precision_at_k | 20 | 1.0000 |
| anomaly_plus_threat_score | precision_at_k | 50 | 1.0000 |
| anomaly_plus_threat_score | precision_at_k | 100 | 1.0000 |
| anomaly_plus_threat_score | precision_at_k | 200 | 1.0000 |
| anomaly_plus_threat_score | precision_at_k | 300 | 1.0000 |
| anomaly_plus_threat_score | recall_at_k | 10 | 0.0250 |
| anomaly_plus_threat_score | recall_at_k | 20 | 0.0500 |
| anomaly_plus_threat_score | recall_at_k | 50 | 0.1250 |
| anomaly_plus_threat_score | recall_at_k | 100 | 0.2500 |
| anomaly_plus_threat_score | recall_at_k | 200 | 0.5000 |
| anomaly_plus_threat_score | recall_at_k | 300 | 0.7500 |

## Classification Metrics

| Method | Metric | Value |
| --- | --- | ---: |
| anomaly_only_flag | false_positive_count | 300.0000 |
| anomaly_only_flag | false_positive_rate | 1.0000 |
| anomaly_only_flag | precision | 0.5714 |
| anomaly_only_flag | predicted_positive_count | 700.0000 |
| anomaly_only_flag | recall | 1.0000 |
| threat_score_flag | false_positive_count | 0.0000 |
| threat_score_flag | false_positive_rate | 0.0000 |
| threat_score_flag | precision | 1.0000 |
| threat_score_flag | predicted_positive_count | 400.0000 |
| threat_score_flag | recall | 1.0000 |

## Scenario Summary

| Scenario | Attack-like | Rows | Avg anomaly score | Avg threat score | Security-relevant rows |
| --- | --- | ---: | ---: | ---: | ---: |
| endpoint_scanning | True | 100 | 0.8108 | 88.38 | 100 |
| popular_endpoint_spike | False | 100 | 0.4493 | 27.72 | 0 |
| repeated_error_attempts | True | 100 | 0.6329 | 48.15 | 100 |
| request_burst_scan | True | 100 | 0.8798 | 84.79 | 100 |
| slow_backend_no_security_signal | False | 100 | 0.5647 | 19.76 | 0 |
| static_asset_burst | False | 100 | 0.7401 | 19.90 | 0 |
| suspicious_probe_off_hours | True | 100 | 0.8280 | 82.98 | 100 |
