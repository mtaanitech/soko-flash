# SokoFlash Kenya — Version 11.0.0

A deployable Node.js marketplace application for Kenya, using an Express API, SQLite database, responsive black/orange/white storefront, seller accounts, listings, search and category filters, WhatsApp contact links, listing reports, Paystack boost checkout, verified payment handling, delayed boost activation, and server-side admin controls.

## What is included

- Responsive marketplace home page and product listing cards
- Search and category filters
- User registration, login, JWT sessions, and seller listing dashboard
- Create listings with title, category, description, KSh price, image URL, location, and WhatsApp contact
- Listing reporting and admin moderation
- Paid Featured/Boost placements through Paystack
- Server-side Paystack webhook signature validation and transaction verification
- Idempotent payment references; boosts remain Pending for the configured delay after verification
- Boost duration begins when the boost activates, not when payment starts
- Admin overview, listing moderation, report management, boost settings, user restrictions, and audit log API
- SQLite persistence via `DATA_DIR`
- Render deployment manifest and environment-variable example

## Deploy to Render

1. Create a new GitHub repository named `sokoflash-kenya` (do not use the MtaaniHost repository).
2. Upload all files from this project to the repository root, including the `public` folder and hidden files such as `.gitignore` and `.env.example`.
3. In Render, create a **Web Service** connected to this repository. Build command: `npm install`. Start command: `npm start`.
4. Add these environment variables in Render:
   - `NODE_VERSION` = `20`
   - `JWT_SECRET` = a long random secret, at least 32 characters
   - `PUBLIC_URL` = your exact public HTTPS Render URL
   - `PAYSTACK_SECRET_KEY` = your Paystack secret key (keep private)
   - `PAYSTACK_PUBLIC_KEY` = your Paystack public key
   - `ADMIN_EMAIL` = the email to bootstrap the first admin account
   - `ADMIN_PASSWORD` = a strong initial admin password
   - `DATA_DIR` = `/var/data` when a persistent disk is attached; otherwise leave unset for the default `./data`
5. For durable database storage, attach a persistent disk to the service and mount it at `/var/data`, then set `DATA_DIR=/var/data`. If you deploy on a plan/platform without persistent disks, SQLite data can be lost on redeploy/restart; use a persistent disk or migrate to a managed database before accepting real customers.
6. In Paystack dashboard, configure the webhook URL as `https://YOUR-SERVICE.onrender.com/api/paystack/webhook`. Use Paystack test keys first and test checkout, webhook delivery, verification, and the delayed activation cycle before using live keys.
7. Visit the deployed URL and create/sign in with the admin account configured before the database's first boot. Admin privileges are enforced on the server.

## Local run

Requires Node.js 20+ and a compiler/runtime compatible with `better-sqlite3`.

```bash
cp .env.example .env
# Edit .env with a unique JWT_SECRET and test Paystack keys
npm install
npm start
```

Open `http://localhost:10000`.

## Payment and safety notes

- Never place `PAYSTACK_SECRET_KEY`, `JWT_SECRET`, or `ADMIN_PASSWORD` in browser code or commit real values to GitHub.
- Do not trust payment screenshots. The server checks Paystack webhook signatures and verifies transactions against Paystack.
- Start with test keys. Confirm the webhook and delayed boost activation on your deployment before receiving live payments.
- Game-account transfers may violate the relevant game's terms. Review the platform rules and local law before allowing those listings; remove prohibited or fraudulent listings.
- Advertising income is not automatically enabled by this code. Apply to an ad network (such as AdSense), obtain approval, and add its approved tags/consent configuration before ads can earn revenue. Never generate fake views or clicks.

## Release status

This is the **Version 11 code release**, not a claim of independent security certification. Before launch with real money, test on the target host, configure backups and monitoring, add legal/privacy/terms and dispute processes, and review payment and moderation flows. Some admin capabilities are available through protected API endpoints and may need more dashboard UI for day-to-day operations.
