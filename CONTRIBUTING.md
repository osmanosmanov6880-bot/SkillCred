# Contributing to SkillCred

Thank you for helping make practical-skill evidence portable and verifiable. Contribution is voluntary; no contributor gains permanent authority by contributing more code or money.

## Before opening a change

1. Search existing issues and the current specification.
2. For material changes, open an issue describing the problem, alternatives, compatibility implications and privacy/security impact.
3. Keep changes small enough for independent review.
4. Never include private keys, learner records, passphrases or production credential data in source control or tests.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pre-commit install
make test
make lint
```

## Code and test expectations

- Python 3.11+, type hints for public functions, explicit errors and no hidden network calls in credential verification.
- Add tests for successful flows, malformed input, tampering, privacy and failure paths.
- Do not implement cryptographic primitives by hand. Use maintained cryptographic libraries.
- Do not silently change signed fields, canonicalization, key formats, status semantics or credential contexts.
- Avoid adding personal-data collection. If data processing is proposed, document purpose, necessity, retention and access.
- Update `SPEC.md` and relevant threat/compatibility notes for changes that affect emitted credentials.
- Do not claim Open Badges certification until external conformance tests pass.

## Review process

- All material changes need at least one reviewer who did not author the change.
- Cryptographic, status-list, key-storage and privacy-sensitive changes require two independent reviews before release when the project has enough maintainers to provide them.
- CI must pass. A passing CI run is necessary but not sufficient; reviewers must inspect the design and compatibility effects.
- Material objections receive a written disposition. Maintainers must not dismiss an objection solely because the objector is less active or is critical of leadership.
- If consensus fails, record the disagreement and use the appeal/mediation process in `GOVERNANCE.md`. Do not use personal attacks, harassment or retaliation.

## Release rules

- Release tags must identify the source commit and generated package artifacts.
- Only authorized release maintainers sign release artifacts; release keys and permissions must be held by more than one trusted maintainer where operationally possible.
- Security fixes may be fast-tracked, but must receive retrospective review and a public security note when disclosure is safe.

## Contributor conduct

Be respectful, assume good faith without ignoring evidence, protect private information, and focus review on claims, code and outcomes. Disagreement is expected and is not misconduct by itself.
