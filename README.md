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

Import the repository and set the Vercel Root Directory to `apps/web`. Configure `MONGODB_URI`, `MONGODB_DB`, and `SESSION_TTL_HOURS` in Vercel. Do not retain `ADMIN_PASSWORD` after seeding or resetting. Use a least-privilege Atlas database user.
