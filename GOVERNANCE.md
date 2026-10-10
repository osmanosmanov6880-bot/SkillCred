# SkillCred governance model

Version: 0.3.0 — proposed governance for the pilot. It is not yet a legally constituted organization.

## Purpose

Protect SkillCred as shared, useful infrastructure rather than a privately controlled gatekeeper. The project exists to make skill evidence more portable and verifiable while preserving learner autonomy, privacy, due process and the right to use alternatives.

## Bodies and separation of powers

1. **Community charter** — defines mission, rights, non-negotiable constraints and the amendment process.
2. **Technical council** — stewards specifications, implementation quality, compatibility and security. It does not control the budget or appoint all its own members.
3. **Participant council** — represents users, implementers, educators and other stakeholders; sets priorities and approves the budget.
4. **Independent review** — reviews finance, conflicts of interest, complaints, security incidents and governance compliance. Reviewers must disclose conflicts and cannot be selected solely by the people they audit.
5. **Independent implementations/operators** — demonstrate that the software and format do not depend on one operator. They can implement the published protocol without permission from the original author, subject to the license and applicable law.

At the early pilot stage, a small group may perform several operational tasks, but no individual should simultaneously have unchecked authority over credential rules, private keys, funds, member access and appeals.

## Proposed council rules

- Participant council: 7–11 seats once a sufficiently broad community exists.
- Term: 3 years; no more than two consecutive terms for the same seat.
- Seats should include implementers, issuing organizations, learners/recipients and independent expertise.
- No employer, funder or set of commonly controlled entities may control a majority of seats.
- Publish agendas, minutes, material decisions, budgets, conflicts of interest and dissenting opinions, subject to privacy and legitimate security exceptions.
- Important changes receive at least 30 days of public notice. A charter amendment requires a two-thirds vote of the participant council and a public comment period, plus approval under the legal entity's applicable rules.
- An independent review or mediation path is available for procedural complaints.
- The founder has no permanent veto, irremovable seat or exclusive ownership of community governance.

These are proposed design defaults, not empirical laws. They should be revised transparently if pilot evidence shows they are ineffective or inaccessible.

## Financial concentration thresholds

- **More than 40% of annual operating income from one source:** trigger a published diversification and dependency plan.
- **More than 60% from one source:** critical concentration; freeze non-essential expansion until the council has reviewed a contingency plan and recorded any donor conditions.
- **More than one third of council seats held by one related group:** mandatory review of representation and conflicts.
- **Any single actor with unilateral authority over charter amendments, key custody, all release signing, and complaint outcomes:** prohibited concentration, regardless of funding share.

These percentages are project-selected alert thresholds, not universal legal limits. Funding concentration is not itself evidence of misconduct, but no grant or customer contract may buy unreviewable control over the project.

## Participant rights

- Read the public specification and change history.
- Submit proposals and receive a reasoned disposition.
- Disagree with leadership without retaliation for the disagreement itself.
- Appeal procedural errors.
- Export personal data and credentials in documented formats.
- Leave the platform without losing rights to credentials already held.
- Request correction/deletion of personal data where applicable law provides such rights.
- Know what data the project processes and why.

## Incident and conflict handling

1. Acknowledge a report and preserve relevant evidence.
2. Assign an unconflicted reviewer.
3. Distinguish technical errors, policy disagreements, privacy incidents and abuse claims.
4. Give affected parties an opportunity to respond, unless doing so would create an immediate safety risk.
5. Record the decision and rationale, redacting personal or exploitable details where necessary.
6. Provide appeal to a reviewer not involved in the original decision.

## Independence tests

At least annually, run and publish results of:

- six-month founder absence tabletop/exercise;
- loss of the largest funding source scenario;
- clean install and operation by an independent team;
- export and transfer to an alternative implementation;
- review of concentration thresholds and unresolved appeals.

## Governance anti-patterns

- lifetime founder veto;
- opaque donor conditions;
- retaliation for criticism;
- undisclosed related-party conflicts;
- a council that appoints and audits itself without checks;
- mandatory central identity or credential storage without compelling, disclosed necessity;
- closed compatibility rules that block legitimate independent implementations.


## Implementation controls in SkillCred 0.2.0

At the API boundary, issuance (`issuer`), revocation (`revoker`), verification (`verifier`) and administrator (`admin`) tokens are distinct. The runtime enforces role separation, but human governance remains a separate layer: API roles do not grant permanent council seats, and a technical maintainer does not gain governance authority solely by controlling a deployment. The default rate limiter is process-local, so a multi-replica deployment must provide a shared ingress policy.

Project warning thresholds are internal decision triggers, not universal scientific boundaries: more than 40% of annual funding from one source requires a diversification/recovery plan; more than 60% triggers a freeze on discretionary expansion until the plan is reviewed; more than one third of council seats held by a connected group triggers independent review of representation and conflicts. These thresholds prompt review and remediation, not automatic conclusions of misconduct.

## Client access lifecycle governance

Client registration, role grant, scope grant, token issuance, rotation and revocation are administrative operations. The least-privilege default mapping is `issuer -> credential:issue`, `revoker -> credential:revoke`, and `verifier -> credential:verify`; `impact:write` is an optional additional verifier scope. `admin` is a break-glass role and cannot be created by normal client registration unless the operator explicitly enables `SKILLCRED_ALLOW_CLIENT_ADMIN=true`.

Maintain a reviewable register of client purpose, owner organization, granted scopes, expiry policy and review date. Store client metadata encrypted; never store the bearer token in plaintext. Every client should have a named organizational owner, a documented offboarding process, and an expiry/rotation cadence. Token operations are not a substitute for independent governance: production adoption should add approval separation for admin creation and periodic review of unused clients.


## 0.3.0 — client lifecycle and issuer federation governance

Client registration, role grants and token rotation are administrative decisions and must be logged by the deploying operator under a published retention policy. Routine clients receive short-lived scoped JWTs; bootstrap admin credentials are break-glass only. The local encrypted registry is single-writer and cannot be operated as a concurrently writable shared file across replicas.

Issuer discovery does not imply trust. A local operator explicitly pins a DID after out-of-band verification; a pin can be removed at any time. No sponsor, founder or issuer gains authority over other issuers by publishing metadata. Charter changes follow `CHARTER_AMENDMENTS.md`; contribution responsibilities follow `CONTRIBUTOR_LADDER.md`.
