# 1EdTech Open Badges 3.0 conformance harness

This directory is a controlled adapter, not a copy of the proprietary or versioned official test suite. Obtain the suite and access rights directly from 1EdTech, pin the exact release/commit and follow its licensing/usage terms. SkillCred does not claim certification merely because local tests pass.

## Inputs

- `SKILLCRED_1EDTECH_SUITE_DIR`: local checkout of the authorized suite.
- `SKILLCRED_1EDTECH_COMMAND`: command documented by that exact suite release, supplied by a trusted operator. It is executed by a shell and must never be populated from untrusted PR input.
- `SKILLCRED_COMPLIANCE_OUTPUT`: output report path, defaults to `compliance-results/official-suite.log`.

Run `./1edtech/run.sh` from the repository root. The command fails clearly if the suite, command or dependencies are missing. It writes a log and reports exit status; it does not convert failures into success.

The project's official schema/context fetch is separate: `python scripts/fetch_official_schemas.py --output-dir schemas`. The schema manifest records source URLs and hashes. Review changes to upstream schema/context before updating a released pin.

## Expected success

Every required test in the exact official release passes, the runner exits with status 0, no unsupported cryptosuite assumptions are needed, and evidence is stored alongside the exact suite revision and dependency versions. See `expected_results.md` and the root `compliance_report_template.md`.
