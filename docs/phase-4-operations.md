# Phase 4 operations

## Required Vercel environment variables

- `CLOUDINARY_URL`: Cloudinary API environment variable. Reports are uploaded as `authenticated` raw assets under `asm/reports`.
- `INTEGRATION_ENCRYPTION_KEY`: Base64-encoded 32-byte key. Generate once with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"` and keep it stable. Rotating it requires decrypting and re-encrypting existing connector configurations.
- `REPORT_RETENTION_DAYS`: Report lifetime, default `30`.
- `CRON_SECRET`: Used by both scan scheduling and report-retention cron routes.

## Deployment checks

1. Add all production variables to the Vercel project; never commit them.
2. Confirm `/api/health` returns a healthy response.
3. Generate one CSV and one PDF, download each, then confirm the URL expires.
4. Add an integration, run its test delivery, and inspect the delivery status in the UI.
5. Confirm Vercel Cron invokes `/api/cron/retention` with the authorization header.
6. Configure alerts for function error rate, latency, failed cron invocations, and MongoDB/Cloudinary availability.

## Incident response

If an integration secret is exposed, revoke it at the provider, remove the connector, and recreate it. If `INTEGRATION_ENCRYPTION_KEY` is exposed, disable integrations, rotate provider credentials, create a new key, and recreate connectors. If `CLOUDINARY_URL` is exposed, rotate the Cloudinary API secret and update Vercel.

Delivery records intentionally store status and errors, not payloads or credentials. Application logs must follow the same rule.

## Backup and recovery

Enable MongoDB Atlas continuous backups for the production cluster. Run a quarterly restore drill into an isolated non-production cluster and verify counts for admins, assets, findings, reports, and integrations. Cloudinary reports are derived exports; regenerate them from MongoDB rather than treating them as the system of record.

## Release gates still requiring people/infrastructure

- Independent penetration test and remediation verification.
- Accessibility review using keyboard navigation plus automated and manual WCAG checks.
- Load and failure testing against production-like Atlas, Cloudinary, QStash, and integration endpoints.
- Backup restore drill and incident-response tabletop exercise.
