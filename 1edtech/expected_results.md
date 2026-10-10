# Official suite expected results

A successful compliance run must include all of the following:

1. Exact authorized suite revision/identifier is recorded.
2. Official AchievementCredential JSON Schema accepts the emitted credential.
3. Open Badges 3.0 and VC Data Model 2.0 mandatory fields are accepted.
4. Expected JSON-LD contexts are processed without undefined terms or context-loading errors.
5. Supported proof profile validates; altered content and altered signatures fail.
6. Supported BitstringStatusListEntry is accepted by the suite's status validation rules.
7. Unsupported profile features are reported as unsupported, never as pass.
8. Required suite test failures = 0; runner exit code = 0.
9. Report includes timestamp, runtime, suite revision, schema/context hashes and raw log artifact.

If the suite is not available or has no documented runner, result is `BLOCKED`, not `PASS`. Local JSON Schema and unit tests are useful prechecks but do not replace official conformance.
