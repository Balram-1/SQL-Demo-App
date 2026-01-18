# Purging sensitive history (non-destructive plan)

This file describes how to permanently remove sensitive files (for example `data/app.db` or generated HTML snapshots) from your Git history. These steps are destructive to history and require coordination with any collaborators. Do NOT run these commands until you understand the implications.

Recommended tools:
- `git filter-repo` (recommended)
- `bfg` (alternative)

High-level steps (safe approach):

1. Backup repository and inform collaborators
   - Clone the repo as a bundle/backup:
     ```powershell
     git clone --mirror https://github.com/<owner>/<repo>.git repo-backup.git
     ```
   - Save the mirror bundle off-site.

2. Install `git-filter-repo` (if not present)
   - On Windows (with Python):
     ```powershell
     pip install git-filter-repo
     ```

3. Run `git filter-repo` to remove files/blobs
   - Example: remove `data/app.db` and any top-level `*.html` snapshots
     ```powershell
     # Work on a fresh clone (non-bare)
     git clone https://github.com/<owner>/<repo>.git temp-repo
     cd temp-repo

     # Remove paths
     git filter-repo --invert-paths --paths data/app.db --paths *.html
     ```
   - This rewrites all history to remove those paths.

4. Inspect the rewritten history
   - Check `git log --stat` and `git fsck --full` to ensure integrity.

5. Force-push rewritten history
   - You MUST coordinate with collaborators. This will rewrite `main` and any branches you push.
     ```powershell
     git push --force --all origin
     git push --force --tags origin
     ```

6. Invalidate secrets and rotate credentials
   - If any real keys or passwords were present in history, rotate them immediately (API keys, certificates, etc.).

7. Ask collaborators to re-clone
   - After force-pushing, collaborators must re-clone to avoid merge conflicts and dangling refs.

Alternative: BFG Repo-Cleaner
- BFG is simpler for many cases: https://rtyley.github.io/bfg-repo-cleaner/
- Example:
  ```powershell
  # Remove files named data/app.db from history
  java -jar bfg.jar --delete-files data/app.db
  git reflog expire --expire=now --all && git gc --prune=now --aggressive
  git push --force
  ```

Notes & warnings
- Always back up before rewriting history.
- Force-pushing public branches can disrupt forks and CI; plan maintenance windows.
- After purge, consider adding robust `.gitignore` rules (already updated) and avoid committing large vendor files.

If you want, I can prepare an exact `git-filter-repo` command tailored to this repository's current commits and help walk you through the force-push steps.
