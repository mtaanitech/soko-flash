# SokoFlash Kenya

A starter marketplace for Kenya with listings, seller accounts, report controls, Paystack boost payments and an admin view.

## Run locally
1. Install Node.js 20+.
2. Copy `.env.example` to `.env` and replace every placeholder.
3. Run `npm install`, then `npm start`.
4. Open `http://localhost:10000`.

## Render
Create a new GitHub repository for this project, upload these files, create a Render Web Service from that repo, and set the environment variables from `.env.example` in Render.

**Persistence:** this starter uses SQLite under `DATA_DIR`. On Render, attach a persistent disk and set `DATA_DIR` to its mount path (for example `/var/data`). Without a persistent disk, local SQLite data can be lost on redeploy/restart.

**Paystack:** start with test keys. Set the Paystack webhook URL to `https://YOUR-SERVICE.onrender.com/api/paystack/webhook`. The webhook signature is checked and payment references are idempotent. Boost remains Pending for the configured delay after verified payment, then activates and its duration starts.

**Admin:** the first admin account is bootstrapped from `ADMIN_EMAIL` and `ADMIN_PASSWORD`. Set strong values before deployment. Change the password after initial setup. Admin checks happen server-side.

## Important production work
This is a working starter, not a fully audited production marketplace. Add email verification/password reset, stronger abuse controls, image object storage, privacy/terms pages, monitoring, backups, and a reviewed dispute/appeal workflow before accepting live money. Do not sell accounts in ways that violate a game's terms. Never publish secret keys.
