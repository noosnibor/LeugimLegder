# HomeLedger — Cloudflare Household Budget

Responsive personal household budget web app, preloaded with October 2026 worksheet categories. Uses Cloudflare Workers static assets + API, Cloudflare D1 (SQLite) for shared cloud data, and GitHub as the code repository.

## What is included
- Monthly pay cycles, estimated income and actual salary deposits for multiple people.
- Expense categories, per-person budget items, daily transactions and running bank balances.
- Month-to-month comparisons, JSON data export/import.
- Individual email/password logins for household members; administrator adds new login accounts.
- HttpOnly secure login cookie, 14-day session, PBKDF2 hashed passwords, same-origin checks and optimistic synchronization conflict protection.

**Privacy:** The original October category labels, family names and example budget amounts appear in `public/index.html` source code. Create a PRIVATE GitHub repository. Because the client bundle is visible to anyone visiting the public site, remove/replace private seed data before sharing the site URL or deploying publicly if this disclosure is unacceptable. Financial transactions and passwords are stored in D1 and only served to authenticated sessions.

## Requirements
Node.js 20+, GitHub account, Cloudflare account (Workers and D1).

## Initial setup

1. Create a **private** GitHub repository, for example `homeledger`, then upload all the files inside this folder (not the outer zip folder).
2. On your Mac or Dell laptop, clone the private repository and run `npm install`.
3. Log in to Cloudflare: `npx wrangler login`.
4. Create the database: `npx wrangler d1 create homeledger-db`.
5. Copy the displayed `database_id` into `wrangler.jsonc`, replacing `REPLACE_WITH_D1_DATABASE_ID`.
6. Apply database migrations: `npm run db:remote`.
7. Generate a unique random 32+ character bootstrap token and store it as a Cloudflare secret: `npx wrangler secret put BOOTSTRAP_TOKEN` (paste the token at the prompt). **Never commit this token.**
8. Deploy: `npm run deploy`. Cloudflare prints the `https://homeledger-household.<your-subdomain>.workers.dev` URL.
9. Open that URL. The initial setup screen asks for the bootstrap token and the first administrator's name, email and password (minimum 12 characters).
10. Sign in, choose **+ Login** to create individual household member logins. Give members their temporary passwords securely; each member should use **Password** to change it.

## Automatic deployment using GitHub

After manual setup, connect the **private GitHub repository** in Cloudflare Dashboard → Workers & Pages → Create or Import existing repository. Use the Workers build/deploy command `npx wrangler deploy`, and make sure the D1 database ID in `wrangler.jsonc` is valid. Do not store the bootstrap token in GitHub or source control. Alternatively enable the provided `.github/workflows/deploy.yml` GitHub Action by adding GitHub Actions secrets `CLOUDFLARE_API_TOKEN` (Workers deploy and D1 permissions) and `CLOUDFLARE_ACCOUNT_ID` and push to `main`. Avoid using both auto-deployment systems simultaneously.

The GitHub Action deploys application code; you must run the D1 database migration separately when migrations change (`npm run db:remote`).

## Local development

Run `npm run db:local` and `npx wrangler dev`. Set the bootstrap token for local work in an untracked `.dev.vars` file like `BOOTSTRAP_TOKEN=unique-long-local-development-secret`. Your local D1 is separate from production. Browser login requires secure cookies: `localhost` is supported by modern browsers, but if cookies are rejected in local HTTP development use HTTPS via the deployed Worker.

## Limitations and security notes

- All logins currently see and can edit the **same household** budget. Admin alone can create login accounts. There is no per-member spending confidentiality or admin removal UI.
- Administrator provisions temporary passwords manually; no verification, invitation email, password-reset email, 2FA or sign-in throttling yet. Add rate limiting/WAF protections before widespread exposure.
- Concurrent edits have version conflict checks: the second save is refused rather than silently overwriting the first. Export the unsaved local changes as backup before reloading and manually reapply, or avoid simultaneous editing. For more robust multi-user activity, a per-transaction API is recommended.
- Sessions are valid for up to 14 days. Changing your password invalidates other sessions.
- **Backups**: use the built-in JSON export periodically and configure Cloudflare D1 backup policies.
- App is not a bank integration. Bank balances are calculated from manually entered opening balances and transactions.
- Review production security, accessibility, accounting correctness and privacy before relying on this app for sensitive financial data.
