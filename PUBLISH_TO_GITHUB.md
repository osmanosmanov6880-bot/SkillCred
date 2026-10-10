# Publish SkillCred 0.3.0 to GitHub

This package excludes local caches, credentials, private keys, encrypted runtime files, local state and `.env` files. Keep `.env.example`; never commit real secrets.

From a terminal, extract this archive, change into the extracted directory, then run:

```bash
git init
git add .
git status --short
# Review the staged file list. Stop if any secret or runtime-state file appears.
git commit -m "Release SkillCred 0.3.0 and Render deployment configuration"
git branch -M main
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
git tag v0.3.0
git push --tags
```

Replace `OWNER/REPOSITORY` with the repository URL supplied by the project owner. If the repository already contains a README/commit, do not overwrite its history; fetch the remote first and integrate the local tree on top.

For Render, use the Blueprint in `render.yaml`. It requests a Starter web service in Frankfurt with a 1 GB persistent disk mounted at `/var/lib/skillcred`. Supply secrets only in the Render dashboard, not in Git. Set `SKILLCRED_STATUS_LIST_URL` to the final `https://<service-host>/status-list` URL after Render assigns the domain.
