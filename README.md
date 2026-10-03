# ASM Platform

Production-oriented attack surface management platform organized as an npm-workspaces Turborepo. The Next.js application uses Turbopack and deploys from `apps/web` on Vercel.

## Repository structure

```text
apps/
  web/                 Next.js dashboard, API, sessions, and admin scripts
packages/
  config/              Validated server environment
  contracts/           Shared Zod schemas and TypeScript contracts
  database/            MongoDB Atlas client, collections, and indexes
  security/            Password hashing and security constants
turbo.json             Workspace task graph
tsconfig.base.json     Shared TypeScript rules
```

## Local setup

1. Update `apps/web/.env` with your MongoDB Atlas connection details.
2. Set a temporary `ADMIN_PASSWORD` with at least 14 characters, uppercase, lowercase, number, and symbol.
3. From the repository root, run `npm run admin:seed` once.
4. Remove `ADMIN_PASSWORD` from `apps/web/.env`.
5. Run `npm run dev` and open `http://localhost:3000`.

## Password reset

Temporarily add `ADMIN_EMAIL` and the new `ADMIN_PASSWORD` to `apps/web/.env`, then run:

```bash
npm run admin:reset-password
```

The reset revokes all active sessions. Remove the plaintext password afterward.

## Workspace commands

```bash
npm run dev
npm run lint
npm run typecheck
npm test
npm run build
```

Turborepo executes each command only in workspaces that define it and respects package dependencies.

## Vercel

Import the repository and set the Vercel Root Directory to `apps/web`. Configure these variables:

```text
MONGODB_URI
MONGODB_DB
SESSION_TTL_HOURS
APP_URL
QSTASH_TOKEN
QSTASH_CURRENT_SIGNING_KEY
QSTASH_NEXT_SIGNING_KEY
CRON_SECRET
```

`APP_URL` must be the deployed HTTPS origin without a trailing slash. Copy the QStash values from Upstash Workflow. Vercel supplies `CRON_SECRET` to authenticated cron invocations when it is configured in the project.

Do not retain `ADMIN_PASSWORD` after seeding or resetting. Use a least-privilege Atlas database user.

## Phase 2 scanning boundary

Automated passive scans require DNS TXT or HTTPS file ownership verification. The scanner performs DNS, Certificate Transparency, RDAP, TLS, and HTTPS header discovery. Connections are pinned to a pre-validated public address; private, loopback, link-local, documentation, multicast, and metadata destinations are rejected. IP and CIDR records are inventory-only until a later ownership mechanism is introduced.

## Phase 3 findings and risk

Completed scans automatically evaluate normalized observations for certificate trust and expiration, missing browser security headers, server technology disclosure, HTTP errors, and unmanaged certificate-backed subdomains. Findings use deterministic fingerprints for deduplication, reopen when they recur, and resolve when absent from a later completed scan.

Risk scores retain severity, confidence, exposure, asset criticality, and exploitability factors. Findings support investigation, resolution, false-positive handling, expiring risk acceptance, comments, bulk status updates, SLA deadlines, and immutable activity events. The dashboard reports live exposure metrics, severity distribution, top risks, SLA pressure, and historical risk snapshots.
