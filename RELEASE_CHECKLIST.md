# SkillCred 0.3.0 Release Checklist

## Source and package
- [ ] `pyproject.toml`, `skillcred.__version__`, API health endpoint, changelog and tag all say 0.3.0.
- [x] Local `python -m pytest --cov=skillcred --cov-report=term --cov-report=json:.coverage-final.json -q`: 168 passed, 3 skipped, 85.95% coverage. Official/optional skipped checks are documented in `VALIDATION_REPORT.md`.
- [ ] Ruff passes on a clean supported Python environment.
- [ ] Python 3.11, 3.12 and 3.13 CI matrix passes.
- [ ] Wheel and sdist build and install in a clean environment.
- [x] Local release validator passes against build artifacts and source bundle (after final rebuild).
- [ ] ZIP and Markdown file inventory match; no local state, secrets, keys, credentials, caches or generated build files are packaged.
- [x] SHA-256 checksums regenerate and verify locally; signature trust still requires the verified release key.

## Security and conformance
- [ ] Review `PENTEST_REPORT.md`; treat it as desk review, not independent penetration test.
- [ ] Verify bootstrap admin credential storage and client JWT rotation/revocation procedure.
- [ ] Verify encrypted wallet/client registry backups and separate key custody.
- [ ] Run Redis rate-limit tests against a real Redis service; verify fallback alarm and reverse-proxy quotas.
- [ ] Run full JCS vectors with `rfc8785` and JSON-LD processing with PyLD.
- [ ] Run official 1EdTech Open Badges conformance suite with trusted, version-pinned assets.
- [ ] Independently review issuer DID pinning ceremony and status-list freshness.
- [ ] Test TLS, CORS/proxy behavior, request limits, recovery and monitoring in the target deployment.
- [ ] Confirm retention/deletion rules, data-processing agreements and consent for the specific pilot jurisdiction.

## Signing and publication
- [ ] Sign the release checksum manifest with the actual release maintainer's GPG/cosign key.
- [ ] Publish the signing-key fingerprint out of band; do not treat a locally generated test key as trusted maintainer identity.
- [ ] Attach wheel, sdist, source ZIP, Markdown dump, SHA-256 list, signature, public key and validation report.
- [ ] Publish limitations and skipped tests alongside artifacts.

## Pilot
- [ ] Data minimization, participant consent and DPA approved for the relevant jurisdiction.
- [ ] At least three independent pilot organizations enrolled.
- [ ] Incident contact and deletion/retention procedures operational.
- [ ] External operator has completed independent recovery drill.
