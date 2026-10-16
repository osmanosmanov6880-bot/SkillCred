# Download and verify the complete source bundle

The repository workflow **Full source ZIP** packages the exact commit checked out by GitHub Actions. It builds the source archive and a path-addressed Markdown dump, then produces a SHA-256 manifest for both.

## Where to download

1. Open the repository's **Actions** tab.
2. Open the latest successful **Full source ZIP** run on the `main` branch.
3. Download the artifact named `SkillCred-complete-source-<commit-sha>`.
4. Extract that downloaded artifact ZIP. It contains the versioned source ZIP, the Markdown source dump, and `SHA256SUMS`.

The workflow retains its artifact for **14 days**. Download a copy to keep it beyond that retention window. The workflow artifact is a build output, not a permanent GitHub Release.

## Verify the files

Run this in Git Bash from the extracted directory:

```bash
sha256sum -c SHA256SUMS
```

On Windows PowerShell, calculate the hashes and compare them with the entries in `SHA256SUMS`:

```powershell
Get-ChildItem .\SkillCred-*.zip | Get-FileHash -Algorithm SHA256
Get-ChildItem .\SkillCred-*-source.md | Get-FileHash -Algorithm SHA256
```

The ZIP contains source and project documentation. It intentionally excludes local runtime data, credential output, private key files, token files, wallet files, virtual environments, caches, and build output.

## Rebuild locally

From the repository root, after installing Python 3.11 or later:

```bash
python scripts/create_release_bundle.py --root . --output-dir dist
cd dist
sha256sum SkillCred-*.zip SkillCred-*-source.md > SHA256SUMS
sha256sum -c SHA256SUMS
```

Release archives must be checked against the manifest from the same build. Do not treat the presence of source files or a successful package build as proof of 1EdTech certification; SkillCred remains a pilot profile and makes no certification claim.
