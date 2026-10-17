# Git Setup (repo already exists)

**Repo:** https://github.com/Mo3z-Sec/Datathon-SOC (public, branch `main`)

You're being added as collaborator. Once Moe adds you:

## 1. Clone (already done here) & create branch
This workspace already has the repo cloned.

Create your working branch:
```bash
git checkout -b nour/data-pipeline
```

## 2. First push (browser login, no gh CLI needed)
Git 2.55 + Git Credential Manager on Windows will pop up a browser login.

```bash
git add nour_data_pipeline
git commit -m "Add Nour data pipeline: clean split, hospital assets, privacy demo, accuracy test"
git push -u origin nour/data-pipeline
```

Git will redirect you to GitHub to sign in. Accept the permissions once.

## 3. Large files rule
`.gitignore` excludes:
- `data/` (raw downloads, can be GB-sized)
- `outputs/cicids_*.csv`, `outputs/unsw_*.csv` if > 100MB (we leave committing policy flexible; commit small ones, share big ones via Drive)

## 4. Never commit secrets
`secret.key` is gitignored. Do not paste keys in code. If you ever regenerate, just keep it local.

## 5. Verify
Check branch appears at https://github.com/Mo3z-Sec/Datathon-SOC/tree/nour/data-pipeline.