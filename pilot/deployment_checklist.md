# External Pilot Deployment Checklist

- [ ] Verify source archive checksum and package version.
- [ ] Install from a reviewed source checkout in a clean environment.
- [ ] Generate strong, separate role tokens (issuer/revoker/verifier/admin).
- [ ] Store `SKILLCRED_API_TOKENS` in a secret manager or protected secret file.
- [ ] Store `SKILLCRED_KEY_PASSPHRASE` in a secret manager or protected secret file.
- [ ] Confirm encrypted `issuer-wallet.scw` exists and no plaintext private-key file remains.
- [ ] Restrict listener to loopback/private network and terminate TLS at a trusted proxy when remote access is required.
- [ ] Configure firewall, backups, patching, monitoring, and incident contact.
- [ ] Run `make test` and record Python/runtime/dependency versions.
- [ ] Test separate role permissions, rate limit, issuance, independent verification, revocation and recovery.
- [ ] Review `THREAT_MODEL.md` and document accepted residual risks.
- [ ] Obtain participant consent and use synthetic data first.
- [ ] Set retention and deletion dates.
- [ ] Run the independent deployment script as a separate operator.
- [ ] Do not call the system Open Badges certified unless 1EdTech has confirmed certification for the product and role.
