# Case-Validation Summary

This report summarizes a selected suspicious production period after anonymization and path generalization. It is used as a supplementary validation example for the dashboard and thesis discussion. Raw logs remain private and are not included here.

- Model version used for scoring: `request_iforest_20260615_223730`
- Request rows in case-validation subset: 240
- Suspicious rows after refined path rules: 34
- Distinct anonymized IP hashes: 5

## Highest-Priority Case Window

| Request count | Suspicious paths | Error count | Error rate | Unique endpoints | Threat score | Level |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 31 | 31 | 30 | 0.968 | 30 | 83.00 | critical |

## Interpretation

The highest-priority window combines repeated suspicious path probes, a high error rate, broad endpoint access, and a high anomaly score. It is treated as a case-validation example showing that the framework can prioritize suspicious behavior for review. It is not used as proof of compromise or attribution.

