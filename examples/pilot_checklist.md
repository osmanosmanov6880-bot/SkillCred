# SkillCred: checklist of the 90-day external pilot

## Days 1–15 — validate the problem

- [ ] Conduct at least 15 interviews across learners, educators, employers and community operators.
- [ ] Describe the existing process and measure time/cost for confirming one skill.
- [ ] Record current alternatives and why participants would or would not switch.
- [ ] Do not collect personal data that is not essential to the interview.
- [ ] Gate: continue only if several independent participants describe the same material problem.

## Days 16–30 — specification and governance

- [ ] Compare the proposed credential fields with the official Open Badges 3.0 JSON Schema and conformance guide.
- [ ] Record all deliberate profile restrictions in `SPEC.md`.
- [ ] Publish the proposed contribution and decision process.
- [ ] Define how a learner can export a credential and how an issuer publishes status updates.
- [ ] Gate: no unsupported claim of Open Badges certification or complete interoperability.

## Days 31–45 — working version

- [ ] Issue one credential with an Ed25519 proof.
- [ ] Verify it in a fresh process with no network access.
- [ ] Change a signed field and verify that verification fails.
- [ ] Export a credential and verify the exported copy.
- [ ] Ensure logs never contain private keys or unnecessary subject identifiers.

## Days 46–60 — portability and robustness

- [ ] Run deterministic proof tests and malformed-input tests.
- [ ] Verify status-list signature and bounds handling.
- [ ] Test invalid, missing and revoked status entries.
- [ ] Run lint, unit, API and end-to-end tests in CI.
- [ ] Record unsupported fields, algorithms and contexts.

## Days 61–75 — independent participants

- [ ] Recruit at least 3 organizations that are independent of the project owner.
- [ ] Ask each to complete the documented flow without help from the author.
- [ ] Have one external operator install and run the project from a clean environment.
- [ ] Measure success rate, time to integrate, support required and stated willingness to continue.
- [ ] Collect issues through a public, accessible channel.

## Days 76–90 — review and decision

- [ ] Publish results, failures, limitations, cost model and unresolved issues.
- [ ] Resolve critical security issues before using real learner data.
- [ ] Confirm no single person is the sole holder of required operational knowledge.
- [ ] Decide explicitly: continue, change direction, or stop.

## Acceptance metrics

| Metric | Pilot threshold | Evidence |
|---|---:|---|
| User interviews | >= 15 | Redacted research summary |
| Independent pilot organizations | >= 3 | Participation confirmations |
| Valid test credentials verified after export | >= 90% | Reproducible test report |
| External clean install | >= 1 team | Recorded run instructions/results |
| Unresolved critical vulnerabilities before real use | 0 | Security review record |
| External feedback | 100% registered with status | Public issue log or redacted report |
| Verified benefit | Baseline and post-pilot comparison | Measured time/cost/quality |
