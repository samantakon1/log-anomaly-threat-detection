# Dataset Quality Summary

This report is generated from anonymized/generalized log files only. It must not include raw IP addresses, user identifiers, tenant names, domains, payloads, tokens, or client names.

## Request Logs: 30-Day Dataset

- Rows: 50,000
- Columns: 28
- Time range: 2026-06-07T14:33:14.691641+00:00 to 2026-06-07T22:57:47.228604+00:00
- Unique IP hashes: 521
- Unique endpoint templates: 928
- Suspicious path rows: 2,512
- Sensitive query rows: 0
- Average latency: 184.708 ms
- P95 latency: 518.622 ms
- Maximum latency: 8474.926 ms

### Request Status Families

| Value | Count |
| --- | ---: |
| 3xx | 22846 |
| 2xx | 22382 |
| 4xx | 4769 |
| 5xx | 3 |

### Request Endpoint Groups

| Value | Count |
| --- | ---: |
| application_route | 22733 |
| api | 12228 |
| static_asset | 10294 |
| versioned_api | 2903 |
| suspicious_probe | 1566 |
| root | 276 |

### Request User-Agent Categories

| Value | Count |
| --- | ---: |
| desktop_browser | 35041 |
| other | 13679 |
| mobile_browser | 990 |
| script_or_api_client | 190 |
| bot | 97 |
| missing | 3 |

## Structured Application Logs: 7-Day Dataset

- Rows: 9,623
- Columns: 28
- Time range: 2026-06-07T18:15:12.991199+00:00 to 2026-06-07T22:53:06.843649+00:00
- Unique user hashes: 173
- Unique tenant hashes: 122
- Unique endpoint templates: 48
- Error rows: 1,105
- Suspicious path rows: 204
- Request sensitive-key rows: 0
- Average response time: 246.98 ms
- P95 response time: 593.0 ms
- Maximum response time: 3682.0 ms

### Application Log Levels

| Value | Count |
| --- | ---: |
| info | 7160 |
| error | 2463 |

### Application Status Families

| Value | Count |
| --- | ---: |
| missing | 6873 |
| 2xx | 2132 |
| 4xx | 618 |

### Application Endpoint Groups

| Value | Count |
| --- | ---: |
| root | 3972 |
| versioned_api | 2754 |
| application_route | 2693 |
| suspicious_probe | 204 |

## Implementation Notes

- These summaries confirm the first implementation can load the anonymized datasets and generate thesis-ready descriptive statistics.
- The request-log dataset remains the primary implementation dataset because it has the largest row count and richer web request behavior.
- The structured application-log dataset supports user-, tenant-, and error-oriented feature analysis after request-log baseline processing.
