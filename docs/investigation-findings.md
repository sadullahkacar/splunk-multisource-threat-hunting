# Investigation Findings

## Overview

This investigation analyzed web access and Linux SSH authentication telemetry in Splunk to identify unusual source-IP behavior and determine whether activity observed across separate log sources overlapped in time.

The investigation progressed from individual web-log analysis to cross-source correlation, temporal analysis, geolocation enrichment, and multi-signal risk scoring.

## Data Sources

The investigation used two primary telemetry sources:

- Web access logs (`index=web`, `sourcetype=access_combined`)
- Linux SSH authentication logs (`index=security`, `sourcetype=linux_secure`)

The web dataset contained 39,532 events across three web servers.

The SSH dataset contained 25,099 failed password events used for authentication threat analysis.

## Web Source-IP Profiling

Source IPs were profiled using:

- Total HTTP requests
- Unique requested URIs
- HTTP 4xx client errors
- Number of targeted web hosts
- URI diversity
- HTTP error rate

This provided a behavioral view of source activity before applying cross-log correlation.

## URI Investigation

URI paths were normalized by separating the request path from query parameters.

Common paths included application endpoints such as:

- `/cart.do`
- `/product.screen`
- `/category.screen`
- `/oldlink`
- `/product.do`

A separate hunt tested for several common suspicious URI patterns, including:

- Administrative and authentication discovery
- Sensitive-file discovery
- Path traversal patterns
- Injection-like patterns

No events matched the defined suspicious URI rules.

This was treated as an investigation finding rather than evidence of an attack.

High URI diversity was therefore not treated independently as proof of malicious scanning because query-string and session variations can increase the number of unique full URIs.

## Cross-Log Correlation

Web and SSH telemetry used different source-IP field structures.

The fields were extracted separately and normalized into a common `src_ip` field using `coalesce()`.

This allowed HTTP activity and failed SSH authentication activity to be correlated by source IP.

Several source IPs appeared in both telemetry sources.

For example, `87.194.216.51` generated:

- 1,036 HTTP requests
- 730 failed SSH authentication attempts

This overlap alone does not establish malicious intent or compromise.

## Temporal Correlation

The investigation was narrowed to one-hour windows.

A source IP was considered temporally correlated when it generated both:

- HTTP activity
- Failed SSH authentication activity

within the same one-hour window.

This produced 183 correlated source-IP/hour observations.

Temporal correlation provided stronger investigative context than simply observing the same IP somewhere in both datasets.

However, correlation still does not prove compromise or common malicious intent.

## Geolocation Enrichment

Splunk's `iplocation` command was used to enrich public source IP addresses with geographic information.

Country and city information was used for investigation and dashboard context.

Geolocation represents source-IP enrichment only and should not be interpreted as proof of an attacker's physical location.

## Multi-Signal Risk Scoring

A lab-tuned scoring model combined several signals:

- Failed SSH authentication volume
- HTTP request volume
- Concurrent HTTP and SSH activity
- Number of targeted SSH hosts
- Number of targeted web hosts

Risk scores were classified as:

- Critical: 80+
- High: 60–79
- Medium: 40–59
- Low: below 40

The scoring weights and thresholds were created for this lab and are not presented as production-validated thresholds.

## Risk Model Results

The 183 temporally correlated observations were classified as:

| Severity | Observations |
|---|---:|
| Critical | 2 |
| High | 12 |
| Medium | 49 |
| Low | 120 |
| **Total** | **183** |

The final detection filtered out Low-severity observations.

This resulted in 63 Medium, High, or Critical detection results.

## Detection Operationalization

The final detection was converted into a scheduled Splunk alert:

**Multi-Source High-Risk Web and SSH Activity**

The alert was configured to:

- Run hourly
- Evaluate a historical one-hour analysis window
- Trigger when the search returns one or more detection results
- Add triggered detections to Splunk's Triggered Alerts interface

Because the lab uses historical telemetry, no fired alert event is claimed.

## Key Takeaways

The investigation demonstrates a progression from individual log analysis to multi-source detection engineering:

**Raw Logs → Field Extraction → Behavioral Profiling → Cross-Log Correlation → Temporal Correlation → Enrichment → Risk Scoring → Detection → Alerting**

The strongest finding was not evidence of a specific web exploit. Instead, the investigation identified source IPs exhibiting concurrent HTTP and failed SSH authentication activity and developed a repeatable method for prioritizing that behavior for analyst review.
