# Threat Scoring Summary

- Model version: `request_iforest_20260623_221511`
- Source table: `analytics.request_ip_anomaly_scores`
- Output table: `analytics.request_ip_threat_scores`
- Rows scored: 2,918
- Security-relevant rows: 118
- High or critical rows: 9

## Threat Level Counts

| Level | Count |
| --- | ---: |
| critical | 5 |
| high | 4 |
| medium | 109 |
| low | 2,800 |

## Top Threat-Scored Windows

| Threat score | Level | Anomaly score | Request count | Suspicious paths | Error rate | Unique endpoints | Reasons |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 100.00 | critical | 1.0000 | 768 | 267 | 0.5859 | 181 | very high anomaly score, large number of suspicious path probes, high error rate with repeated failures, high request burst, very broad endpoint access pattern |
| 83.83 | critical | 0.8522 | 495 | 56 | 0.1838 | 39 | very high anomaly score, repeated suspicious path probes, large number of error responses, elevated request volume, broad endpoint access pattern, activity occurred during off-hours |
| 82.88 | critical | 0.9967 | 31 | 31 | 0.9677 | 30 | very high anomaly score, repeated suspicious path probes, high error rate with repeated failures, broad endpoint access pattern |
| 81.93 | critical | 0.7980 | 333 | 46 | 0.1772 | 30 | high anomaly score, repeated suspicious path probes, large number of error responses, elevated request volume, broad endpoint access pattern, activity occurred during off-hours |
| 80.95 | critical | 0.8844 | 309 | 31 | 0.2265 | 41 | very high anomaly score, repeated suspicious path probes, elevated error rate, elevated request volume, broad endpoint access pattern |
| 65.49 | high | 0.8425 | 575 | 0 | 0.1635 | 89 | very high anomaly score, large number of error responses, high request burst, broad endpoint access pattern, activity occurred during off-hours |
| 64.70 | high | 0.7058 | 280 | 24 | 0.1929 | 17 | high anomaly score, repeated suspicious path probes, large number of error responses, elevated request volume |
| 62.28 | high | 0.6938 | 266 | 31 | 0.0414 | 32 | high anomaly score, repeated suspicious path probes, elevated request volume, broad endpoint access pattern |
| 62.11 | high | 0.6888 | 286 | 33 | 0.0420 | 33 | high anomaly score, repeated suspicious path probes, elevated request volume, broad endpoint access pattern |
| 57.26 | medium | 0.7217 | 173 | 14 | 0.2370 | 21 | high anomaly score, suspicious path pattern present, elevated error rate, elevated request volume |
| 57.25 | medium | 0.7785 | 144 | 13 | 0.2153 | 18 | high anomaly score, suspicious path pattern present, elevated error rate, activity occurred during off-hours |
| 56.55 | medium | 0.7014 | 86 | 4 | 0.4535 | 40 | high anomaly score, suspicious path pattern present, elevated error rate, broad endpoint access pattern |
| 55.87 | medium | 0.7392 | 126 | 11 | 0.2063 | 20 | high anomaly score, suspicious path pattern present, elevated error rate, activity occurred during off-hours |
| 55.33 | medium | 0.7237 | 115 | 11 | 0.2087 | 18 | high anomaly score, suspicious path pattern present, elevated error rate, activity occurred during off-hours |
| 53.68 | medium | 0.6765 | 253 | 24 | 0.0000 | 15 | high anomaly score, repeated suspicious path probes, elevated request volume |
| 53.27 | medium | 0.7219 | 154 | 15 | 0.1104 | 38 | high anomaly score, suspicious path pattern present, elevated request volume, broad endpoint access pattern |
| 52.80 | medium | 0.5943 | 179 | 11 | 0.2011 | 17 | suspicious path pattern present, elevated error rate, elevated request volume |
| 50.72 | medium | 0.5920 | 119 | 12 | 0.2773 | 17 | suspicious path pattern present, elevated error rate, activity occurred during off-hours |
| 50.70 | medium | 0.5915 | 64 | 6 | 0.2031 | 28 | suspicious path pattern present, elevated error rate, activity occurred during off-hours |
| 50.37 | medium | 0.5820 | 52 | 4 | 0.2115 | 16 | suspicious path pattern present, elevated error rate, activity occurred during off-hours |
