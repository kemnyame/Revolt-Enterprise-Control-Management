# Revolt-X IT Control Management 2.0

Organisation-scoped IT assurance and technology operations platform. Plans, risks, a 77-control library, audits/reviews, control testing, evidence, findings/remediation, SLAs, assets, licence renewals, change management, PDF/Excel/CSV reporting and audit packs.

Customer administrators can create users with unique 24-hour temporary passwords. First sign-in requires a personal password. The platform administrator can provision isolated organisations and manage subscription periods. Expired subscriptions are read-only; suspended customers cannot access operational records. Subscription billing and payment collection are managed externally.

## Control workflow

- Named accountable owners and independent reviewers.
- Approval and closure gates, evidence requirements, optimistic locking and idempotent requests.
- Uploaded source bytes and SHA-256 integrity fingerprints.
- Findings require a subsequent independently reviewed passing retest before closure.
- Append-only commercial decisions and recorded core audit actions.
- Sample scenarios are labelled, read-only and excluded from operational notifications.
- Customer workspaces receive control and connector definitions, without another customer's records.

## Licence register

The original 14-column ICDD Excel/CSV format is supported, with preview, row-specific validation, duplicate prevention, quantities, payment history and renewal history. Reminder preparation starts two calendar months before expiry, clamps month ends, and deduplicates reminder buckets. Actual customer data and credentials do not belong in this public source repository.

## Email

Operational and account messages use a database outbox. Enable notifications per organisation. The connected Gmail relay claims eligible messages, submits them using the authorised sender and records the actual provider ID. `GMAIL_RELAY_ACTIVE=1` indicates that the separate delivery task is enabled. Queueing is not delivery. Uncertain attempts require review before retrying. Optional immediate SMTP is available using `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`.

Welcome messages exclude the temporary password; administrators share the credential separately. Reset tokens are hashed at rest, single-use and valid for two hours to accommodate hourly relay processing. Queued reset bodies are scrubbed after submission or expiry. No Gmail OAuth token is copied into this application.

## Running

Use Node 24. Set `DATABASE_URL`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `JWT_SECRET`, `INTEGRATION_ENCRYPTION_KEY` and `ALLOWED_ORIGINS`. In production use HTTPS and a verified-TLS PostgreSQL connection. The bootstrap password only creates a missing administrator; it never overwrites an existing personal password.

`npm ci`, `npm run build`, `npm test`, `npm run dev`.

The install/build phase runs a release gate against `TEST_DATABASE_URL`, which must point to a separate Neon branch. HTTP integration checks cover customer isolation, all work modules, evidence, independent approval, concurrency, import/renewal deduplication, reports, closure, notification claims and session invalidation. Production `npm start` starts the compiled server directly. Cold starts do not rebuild or rerun the release suite, and never create or delete smoke-test records in the live database.

Retained validated connectors: GitHub, Entra ID, Microsoft 365, Jira, ServiceNow, Splunk, Tenable and CrowdStrike. Provider credentials are encrypted with the dedicated integration encryption key.

Framework references in the control catalogue are assessment aids. Application use does not establish certification or regulatory compliance. Set customer-specific assessment criteria and obtain qualified independent assurance when required.
