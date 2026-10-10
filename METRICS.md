# SkillCred metrics and measurement protocol

Every metric needs an owner, data source, baseline, collection frequency and review date. Raw personal data should not be collected solely to measure the project's success.

## A. Public benefit — quarterly

Measure:

- median time and cost for a relying organization to verify a skill before and after adoption;
- percentage of pilot participants who complete their credential workflow without issuer assistance;
- percentage of participating organizations that report concrete operational benefit;
- externally validated cases where a portable credential reduced duplicate assessment or administrative effort.

Rule: compare against the previous process and publish negative or null outcomes. Do not count page views or credential issuance alone as proof of benefit.

## B. Network health — quarterly

Measure:

- independent organizations using the software in real workflows;
- independent compatible implementations/operators;
- retention of organizations at 6 and 12 months;
- time and cost to export and verify credentials using an alternative implementation;
- maintenance contributions from teams unrelated to the project founder.

Rule: departments of the same controlled entity do not count as independent organizations. Track quality of use, not only registrations.

## C. Legitimacy and power distribution — semiannually

Measure:

- percentage of material decisions with public rationale and minutes;
- related-party share of participant-council seats;
- largest-funder share of operating income;
- complaint and appeal counts, median response time, upheld appeals and correction rate;
- participant assessment of procedural fairness, including dissenting participants.

Rule: few complaints do not prove good governance; inspect whether people can safely and easily complain.

## D. Resilience — quarterly and after incidents

Measure:

- financial runway for essential maintenance/security work;
- percentage of critical operations with at least two trained operators;
- successful clean-room deployments and restore exercises;
- recovery time and recovery point achieved in drills;
- critical third-party dependencies without documented alternatives.

Rule: written plans do not count until tested. Record failed drills and corrective actions.

## E. Rights and security — continuous, reported quarterly

Measure:

- critical security/privacy incidents and time to containment/remediation;
- requests for credential/data export and deletion, with completion times;
- successful accessibility checks and documented barriers;
- substantiated abuse-of-power cases, retaliation reports and remedy status;
- status-list freshness failures detected by pilot verifiers.

Rule: avoid logging recipient identifiers and credential contents unless strictly necessary and separately reviewed. Report aggregate values and protect reporters' identities.

## Pilot targets

See `examples/pilot_checklist.md`. Targets such as 15 interviews, 3 independent organizations and 90% successful verification of a fixed test corpus are project-defined decision thresholds, not general evidence that the system is secure or certified.

## Annual report

Publish a yearly report covering all five groups, methodological changes, gaps, uncertainty, concentration thresholds, outstanding incidents, decision to continue/pivot/stop and the rationale for that decision.

## API metrics endpoint (0.2.0)

`GET /metrics` exposes Prometheus text format with bounded labels:

- `skillcred_http_requests_total{method,route,status}` — handled requests.
- `skillcred_http_request_duration_seconds{method,route}` — request latency histogram.
- `skillcred_operations_total{operation,outcome}` — issue, verify and revoke outcomes.
- `skillcred_errors_total{category}` — HTTP/application error counts.

The middleware uses route templates rather than raw paths; unknown paths share `/unmatched`. No credential, subject, token, or client IP labels are emitted. `/health`, `/ready`, and `/metrics` are exempt from the in-process rate limiter to support probes and scraping. Metrics are per process and are not a durable audit log. Protect `/metrics` at the network layer if operational data should not be public.

## Impact metrics endpoint

`POST /metrics/impact` accepts consent-confirmed, low-dimensional pilot records. It measures reduction in verification time, same-currency cost change, satisfaction and credential portability. The report generator `tools/impact_report.py` consumes an authorized JSON export from `GET /metrics/impact` and emits a summary with explicit caveats. Do not include personal identifiers in `organization_ref`; use a random code assigned by the pilot organizer. Groups smaller than three records are suppressed from summaries, while CSV/JSON exports remain administrator-restricted.


## Federation and impact metrics in 0.3.0

Issuer discovery is intentionally not counted as trust or adoption. Impact records measure reported process timing, optional cost, satisfaction and portability with consent; they are descriptive pilot measurements, not proof of causality. CSV and JSON exports are privileged outputs and should have a retention/handling policy.
