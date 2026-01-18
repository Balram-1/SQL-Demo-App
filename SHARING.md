SHARING NOTES — SQLi Demo App

Purpose
- This repository is an intentionally vulnerable demo app for educational SQLi exercises.
- I've cleaned and prepared the repo so it's safe to share with instructors while preserving the learning material.

What I changed (high level)
- Removed noisy one-off temporary scripts from tracked code (they're replaced with short placeholders).
- Ensured the local SQLite DB (`data/app.db`) is not tracked and is in `.gitignore`.
- Replaced hard-coded session secret fallback with a runtime-generated secret unless `SESSION_SECRET` is provided.
- Removed hard-coded seed passwords; use `SEED_*` env vars or the app will generate strong random credentials at runtime and print them to console.
- Preserved audit logs in the DB; destructive cleanup actions were performed earlier and are recorded in `audit_logs`.

Before you run (teacher / reviewer instructions)
1. Clone the repo.
2. Install dependencies:

   npm install

3. Create a `.env` file (copy `.env.example`) and set values if you want repeatable credentials. Example minimal `.env`:

   SESSION_SECRET=your-long-secret-here
   VULN_MODE=on
   SEED_ADMIN_PASSWORD=adminpass123    # optional - set to get a known admin password

4. Start the app:

   node server.js

   - If you didn't set seed passwords, the app will print generated seed credentials to the console during DB initialization.
   - The local database file `data/app.db` is created locally and is NOT pushed to GitHub.

Notes & safety
- Passwords and payment information in this demo are stored in plaintext by design (educational). Do not use any real passwords or real payment details when seeding or testing.
- If you need to reset the demo DB, log in as the admin account and use the admin UI Reset (requires typing the confirmation phrase shown in the UI).
- If you want me to fully remove placeholder scripts (instead of stubbing them), I can do that on request.

Files added for sharing
- `.env.example` — shows recommended environment variables.
- `SHARING.md` — this file, with instructions and a brief change-log.

If you'd like, I can also:
- Produce a short 'how to grade' checklist for your teacher.
- Create a small PowerShell starter script that sets example env values and starts the app.
