# SkillCred MVP profile specification

Status: **experimental pilot profile; not 1EdTech-certified**. Version: 0.3.0.

## 1. Scope

SkillCred provides a small local-first workflow for issuing skill credentials, exporting them as JSON, verifying issuer signatures without network access, and checking revocation using an issuer-published signed status list. It intentionally does not operate a global identity registry, host learner records centrally, or decide whether a credential issuer should be trusted.

Normative external references:

- Open Badges Specification 3.0: <https://standards.1edtech.org/open-badges/specifications/standards/v3p0>
- W3C VC Data Model 2.0: <https://www.w3.org/TR/vc-data-model-2.0/>
- W3C Data Integrity EdDSA Cryptosuites: <https://www.w3.org/TR/vc-di-eddsa/>
- RFC 8785 JCS: <https://www.rfc-editor.org/rfc/rfc8785>
- W3C Bitstring Status List 1.0: <https://www.w3.org/TR/vc-bitstring-status-list/>

## 2. Credential shape

Skill credentials use these JSON-LD context URLs:

- `https://www.w3.org/ns/credentials/v2`
- `https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json`

Bitstring status-list credentials use `https://www.w3.org/ns/credentials/v2`. The MVP does not dereference any of these contexts while issuing or verifying credentials.

The main type is `OpenBadgeCredential`, alongside `VerifiableCredential`. `credentialSubject.achievement` contains an `Achievement` type, a display name and a description. The caller's real-world learner identifier is optional. The current 1EdTech `AchievementSubject` schema specifies that either `id` or at least one `identifier` must be supplied. To preserve no-registration issuance while satisfying that requirement, SkillCred generates a fresh random `urn:uuid:` subject identifier for each credential when no explicit `subject_id` is supplied. It is not derived from personal data and is not stored centrally; different credentials receive different values. This pseudonymous identifier still travels with that credential and can be seen by anyone who receives it. A credential ID is another opaque `urn:uuid:` identifier unless a caller supplies one.

The MVP does not implement the entire Open Badges data model. It omits several optional fields and schemas, and the issuer identifier is a `did:key` derived from an Ed25519 key. Therefore the document is Open Badges-shaped and intended to evolve toward conformance, but passing signature tests is not evidence of full Open Badges 3.0 certification.

## 3. Proof suite

The MVP uses W3C `DataIntegrityProof` with `cryptosuite: eddsa-jcs-2022` and `proofPurpose: assertionMethod`.

Proof creation follows the W3C cryptosuite algorithm:

1. Clone the credential without `proof` as the unsecured document.
2. Build proof options with `@context`, `type`, `cryptosuite`, `created`, `verificationMethod`, and `proofPurpose`.
3. Apply RFC 8785 JCS canonicalization to the unsecured document and the proof configuration.
4. Compute SHA-256 of each canonical representation.
5. Concatenate `proofConfigHash || transformedDocumentHash`.
6. Sign the concatenation with Ed25519.
7. Encode the 64-byte signature as base58-btc multibase (`z...`) in `proofValue`.

The verifier removes `proofValue` from the proof configuration and removes `proof` from the document, repeats the same algorithm, decodes the `did:key` public key and verifies the signature. No network calls are made.

`pyld` is included in the declared stack for future explicit JSON-LD expansion and conformance tooling, but this MVP does not dereference remote contexts during issue or verify. The `eddsa-jcs-2022` suite is based on JSON Canonicalization Scheme rather than RDF dataset canonicalization; using PyLD URDNA2015 normalization in its place would be incorrect. Offline operation deliberately avoids hidden context fetches and the associated privacy and availability risks.

### Canonicalization limitation

The development environment had no access to PyPI, so `rfc8785` could not be installed for local execution. The repository includes a fallback canonicalizer that handles strings, arrays, objects, booleans, null and safe integers, but rejects floats and integers outside JavaScript's safe integer range. Normal installation includes `rfc8785`, which is used for full RFC 8785 support. Production packaging and interoperability tests must confirm this dependency is installed and the fallback is not used for broader payloads.

### Relationship to `Ed25519Signature2020`

`Ed25519Signature2020` is a legacy suite. W3C advises new implementations to use `eddsa-rdfc-2022`. SkillCred does **not** label its proof `Ed25519Signature2020`; the current implementation uses the W3C-defined `eddsa-jcs-2022` cryptosuite. The W3C Data Integrity EdDSA specification defines `eddsa-jcs-2022`, but the 1EdTech Open Badges materials reviewed for this release show other proof suites (`eddsa-rdfc-2022` in credential examples and `eddsa-rdf-2022` in some shared proof-model requirements). Do not assume those names or algorithms are interchangeable. Verify the exact current Open Badges profile, official schema and certification suite before claiming interoperability. Switching to `eddsa-rdfc-2022` requires correct RDF Dataset Canonicalization 1.0; URDNA2015 support alone must not be assumed equivalent.

## 4. Key and identifier model

- Key algorithm: Ed25519.
- Public key multicodec prefix: `0xed01` (Ed25519 public key).
- Public key fingerprint: multibase base58-btc (`z` prefix).
- Issuer DID: `did:key:<fingerprint>`.
- Verification method: `did:key:<fingerprint>#<fingerprint>`.
- Private keys in CLI wallets: encrypted with Scrypt-derived 256-bit key and AES-256-GCM.

The API stores the private key in `issuer-wallet.scw`, encrypted using the wallet's Scrypt-derived key and AES-256-GCM. Configure `SKILLCRED_KEY_PASSPHRASE` or `SKILLCRED_KEY_PASSPHRASE_FILE`; absent a configured passphrase, persistent signing is disabled. A legacy `SKILLCRED_PRIVATE_KEY_B64` secret-injection path remains for controlled migration/secret-manager use and should not be used as checked-in configuration. A public key proves possession of the corresponding private key; it does not by itself prove a legal issuer's identity.

## 5. Status and revocation

Current Open Badges 3.0 examples use `BitstringStatusListEntry`; the W3C `Bitstring Status List 1.0` Recommendation is the relevant current status-list standard. SkillCred does not implement the legacy StatusList2021 model.

The MVP's status-list credential uses:

- type: `VerifiableCredential`, `BitstringStatusListCredential`;
- credential subject type: `BitstringStatusList`;
- `statusPurpose: revocation`;
- `encodedList`: gzip-compressed bitstring encoded using base64url multibase (`u` prefix, no padding);
- 131072 bits (16384 bytes) minimum;
- `BitstringStatusListEntry` with `statusListIndex` and `statusListCredential`.

The first implementation supports revocation only. Bit index zero is the left-most (most-significant) bit in the first byte, as required by the W3C specification. Each issuer manages its own status state. No learner ID is written to the status state file. The list is signed as a Verifiable Credential using the same issuer key.

A verifier needs a signed list snapshot to check current status. Signature verification alone can be performed offline; revocation status cannot be known offline without a supplied current list. A stale list can report an outdated status. The MVP does not yet implement freshness policy, list rotation, expiration, distributed publication or full conformance testing against the W3C suite; do not rely on it for high-stakes decisions until those gaps are addressed.

## 6. Offline verification and trust

`verify_signature` checks cryptographic integrity using only the credential. `verify_credential` additionally checks basic Open Badges type/context shape and, if a status list is provided, its signature, issuer match, URL match and revocation bit.

The verifier does not automatically trust every `did:key`. Relying parties must decide which issuers they accept, for example through a direct out-of-band key exchange, an issuer registry they choose to trust, or a signed trust list. The project does not run a central issuer registry.

## 7. API boundaries

`POST /issue` requires the `issuer` or `admin` role; `POST /revoke` requires `revoker` or `admin`; `POST /verify` requires `verifier` or `admin`. Configure distinct tokens in `SKILLCRED_API_TOKENS` (a JSON role-to-secret map) or `SKILLCRED_API_TOKENS_FILE`. The old `SKILLCRED_API_TOKEN` variable remains as a temporary admin-only compatibility path. Each token must have at least 32 ASCII characters. The built-in fixed-window rate limiter is process-local; multi-worker or multi-replica deployments need a shared limiter/ingress policy. Request bodies are limited to 1 MiB by default, but a trusted ingress should enforce its own limits too. Internet-facing service still needs TLS, token rotation, logging minimization and independent security review. `/health` is a liveness endpoint; `/ready` fails when persistent encrypted signing is unavailable.

## 8. Known omissions before conformance

- Validate every emitted credential and status-list object against the current official 1EdTech Open Badges 3.0 JSON Schema. The subject identifier has been adjusted to meet the schema's documented `AchievementSubject` requirement, but the schema itself could not be fetched in this environment.
- Run the complete 1EdTech conformance and certification test suite.
- Interoperate with multiple independent Open Badges wallets.
- Confirm all status-list encoding and index semantics against the exact latest W3C test suite.
- Support issuer key rotation and compromise recovery.
- Add lock-safe shared state updates for multi-process deployments, signed list freshness/expiry and list rotation.
- Add issuer trust policy, accessible privacy notices, data-protection impact assessment where relevant, and legal review for target markets.


## 9. JCS compatibility and validation boundaries

The runtime uses the `rfc8785` package when installed. A restricted fallback handles strings, literals, arrays, objects, and safe integers; it rejects floating-point values and integers outside the IEEE-754 safe integer range. This fallback is not a complete RFC 8785 implementation. The official RFC §3.2.2 number vector is enabled in the test suite and runs when the package dependency is present. `schemas/openbadge-pilot.schema.json` is a local pilot-profile schema only, not the official 1EdTech schema.

Use `python scripts/check_env.py` to see which validation tools are available. The 1EdTech suite is available through its official certification workflow; use the exact runner from official suite instructions and fill in `compliance_report_template.md`. See <https://standards.1edtech.org/open-badges/specifications/standards/v3p0/cert>.

## 10. API roles, rate limit and metrics

`GET /metrics` exposes Prometheus-compatible low-cardinality request, latency, operation and error counters. Do not add subject identifiers, credential IDs, IP addresses or request payloads as metric labels. The default limiter is in-memory and is not a distributed rate limiter. `Accept-Language: ru` selects Russian for supported messages; English is the fallback. CLI message language is controlled by `SKILLCRED_LANG=ru|en`.

## Client JWT profile (API authorization)

SkillCred API access tokens use compact JWS JWT with `alg=EdDSA`, signed by the issuer's Ed25519 key (RFC 8037). The JOSE header is restricted to `alg`, `typ`, and `kid`. Required claims: `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `ver`, `roles`, and space-delimited `scope`. Tokens are short-lived (60 seconds to 30 days), and the encrypted registry stores only token metadata, never the compact token. The registry rejects revoked `jti` values, revoked clients, and tokens superseded by a rotation version bump. This profile is for API administration and is distinct from a credential proof.

## Impact-record profile

Impact records are local operational research data, not credentials. They contain a pseudonymous organization code, fixed scenario vocabulary, elapsed verification time before/after, optional costs in one ISO 4217 currency, satisfaction (1–5), portability result and a consent flag. No names, emails, student identifiers, IP addresses or free-text values are accepted. Summaries suppress groups smaller than three records by default. The official privacy notice and local retention schedule still apply.

## Open Badges conformance boundary

The distributed `schemas/openbadge-pilot.schema.json` is an internal profile schema, not the official 1EdTech schema. It validates the project's limited credential shape. The official AchievementCredential schema and current JSON-LD context can be fetched into `schemas/` with `scripts/fetch_official_schemas.py` in a network-enabled environment. The release report must record schema URL, SHA-256 and retrieval date. Full conformance requires the official schema, processing under the correct JSON-LD contexts, proof verification as specified by the applicable cryptosuite, and the official 1EdTech conformance tests. A passing local schema test is not a certification claim.


## 0.3.0 federation boundary and standards references

`/.well-known/skillcred-issuer.json` is a SkillCred discovery profile, not a W3C or 1EdTech standard. It only publishes an issuer DID, supported pilot profile, proof suite and status-list URL. It is not signed separately and must not imply trust; operators should confirm the DID out of band and pin it locally. No metadata URL is fetched automatically.

The credential profile targets the published VC Data Model 2.0 Recommendation and Open Badges 3.0, with the W3C `eddsa-jcs-2022` cryptosuite and Bitstring Status List v1.0 style status. This codebase has not passed the official 1EdTech conformance suite and the official schema/context were not available to this environment. The local schema and `skillcred.conformance` checks are structural pilot guards only.

References:
- 1EdTech Open Badges 3.0: https://standards.1edtech.org/open-badges/specifications/standards/v3p0
- Official schema: https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json
- Official context: https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json
- VC Data Model 2.0 Recommendation: https://www.w3.org/TR/vc-data-model-2.0/
- Data Integrity EdDSA: https://www.w3.org/TR/vc-di-eddsa/
- Bitstring Status List v1.0: https://www.w3.org/TR/vc-bitstring-status-list/
