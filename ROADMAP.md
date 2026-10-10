# SkillCred roadmap: October 2026–October 2036

Roadmap stages are gates, not promises of growth. If a stage fails its acceptance criteria, pause, correct or stop rather than scaling to mask failure.

## 2026–2027 — prove the problem and benefit

**Goal:** demonstrate a recurring problem around practical-skill evidence and produce a working prototype.

**Actions:** interview at least 15 prospective users; compare current solutions; implement issuance/export/offline verification; validate the selected profile against official schemas; measure baseline effort and post-pilot outcomes.

**Deliverable:** reproducible prototype, documented limits and evidence of independent user benefit.

**Stop condition:** the interviews fail to establish a material problem, existing solutions are better, or the prototype cannot be used safely within the available resources.

## 2028–2029 — build an independent network

**Goal:** enable independent organizations and teams to issue, verify and maintain compatible credentials.

**Actions:** onboard external pilot organizations; publish compatibility tests; document implementer requirements; accept external contributions; introduce complaint handling and contribution governance.

**Deliverable:** multiple independent users and at least two implementations or independently operated integrations.

**Stop condition:** adoption requires continuous founder intervention, integration cost outweighs demonstrated benefit, or portability claims fail.

## 2030–2031 — establish an independent institution

**Goal:** separate shared infrastructure from the founder's personal control.

**Actions:** adopt the community charter; establish appropriate legal form after jurisdiction-specific advice; create participant and technical councils; commission independent review; diversify funding; document incident and succession procedures.

**Deliverable:** operating governance, transparent finances, appeal process and tested succession plan.

**Stop condition:** participants do not want to share governance or there is no sustainable budget for maintenance and security.

## 2032–2033 — expand across regions and sectors

**Goal:** prove that the infrastructure can be adapted to different contexts without mandatory centralization.

**Actions:** support localization and accessibility; cooperate with existing standards bodies; fund regional maintainers; keep implementations interoperable; publish context-specific privacy and legal assessments.

**Deliverable:** independent teams in multiple regions can adapt and operate the system.

**Stop condition:** expansion materially worsens privacy, safety, accessibility, representation or interoperability.

## 2034–2035 — test resilience under stress

**Goal:** discover critical single points of failure before a real crisis.

**Actions:** simulate six months without the founder; simulate loss of the largest funding source; test clean-room deployment; restore from backups; exercise governance conflict and appeal procedures; review key compromise response.

**Deliverable:** published test report, remediated critical failures, working recovery and succession processes.

**Stop condition:** the system cannot recover without giving one actor unchecked power or violating participant rights.

## 2036 — demonstrate institutional maturity

**Goal:** independently prove usefulness, legitimacy and resilience.

**Actions:** commission an external evaluation; renew or transfer leadership; audit concentration of power and funding; test exit and export; publish benefits, failures and unresolved risks.

**Deliverable:** a system that remains useful without its founder, has independent implementations and permits criticism, leadership change and alternatives.

**Stop condition:** unresolved systemic abuse, inability to change leadership, or material claims of public benefit unsupported by evidence.

## Annual review

Publish a short yearly report covering the five groups in `METRICS.md`, financial concentration, unresolved security issues, complaints and appeals, governance changes, failed targets and explicit decisions to continue, pivot or stop.


## Engineering gates introduced in 0.2.0

The release candidate adds role-scoped API tokens, encrypted API signing-key persistence, request-size limits, `/ready`, Prometheus metrics, environment diagnostics, pilot runbook, deployment manifests, and a threat model. These controls improve the bounded pilot posture but do not replace a distributed limiter, official 1EdTech testing, third-party security review, issuer key rotation, or status-list freshness enforcement. Each remains an explicit gate before public or high-impact deployment.
