# ASM Control

Production-oriented attack surface management control plane built with Next.js, Tailwind CSS, and MongoDB Atlas. Phase 1 provides a secure single-admin foundation.

## Local setup

1. Update the included `.env` file with your MongoDB Atlas connection details.
2. Set a temporary `ADMIN_PASSWORD` with at least 14 characters, uppercase, lowercase, number, and symbol.
3. Run `npm run admin:seed` once.
4. Remove `ADMIN_PASSWORD` from `.env`.
5. Run `npm run dev` and open `http://localhost:3000`.

## Password reset

Temporarily add `ADMIN_EMAIL` and the new `ADMIN_PASSWORD`, then run:

```bash
npm run admin:reset-password
```

The reset revokes all active sessions. Remove the plaintext password from the environment immediately afterward.

## Quality checks

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

## Vercel

Configure `MONGODB_URI`, `MONGODB_DB`, and `SESSION_TTL_HOURS` in Vercel. Do not leave `ADMIN_PASSWORD` configured after seeding or resetting the account. Ensure Atlas network access permits Vercel connectivity and uses a least-privilege database user.
