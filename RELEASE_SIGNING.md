# Release artifact signing

## Maintainer release

The tagged GitHub release workflow requires repository secrets `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`. It fails closed if either is missing. The workflow imports the maintainer key, exports the corresponding public key, builds `SHA256SUMS` over the wheel, sdist, source ZIP, source dump, release-validation JSON and public key, and creates an ASCII-armored detached GPG signature `SHA256SUMS.asc`.

Before trusting a release, users must obtain the expected maintainer key fingerprint from an independent, authenticated channel and compare it with the fingerprint of the downloaded public key. A self-published key file does not authenticate itself. Verify with:

```bash
gpg --import skillcred-release-public-key.asc
gpg --fingerprint
 gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
```

Do not trust a release merely because a signature verifies against an unverified key.

## Locally generated build-session signature

A local build environment without a maintainer signing key may create a short-lived build-session key to demonstrate and test signing mechanics. Such a signature must be explicitly labelled **UNTRUSTED BUILD-SESSION KEY**. It proves only that the manifest has not changed since the holder of that ephemeral key signed it; it does not prove publisher identity, maintainer approval or supply-chain provenance. Do not use this key for the published GitHub release.
