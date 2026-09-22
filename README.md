# Revolt-X Enterprise Control Management

Production-oriented enterprise assurance platform with **IT Controls** as the first commercial module.

## Production application

- Multi-tenant organisation-scoped PostgreSQL model
- JWT authentication with hashed passwords and role-based permissions
- Control register and 77-control IT control library
- Evidence vault with source-file storage, SHA-256 fingerprints, evidence review and integrity verification
- Test Control workflow with objective, procedure, sample, evidence selection, design/operating effectiveness, score and findings
- Findings and remediation with passing-retest requirement before closure
- Reviewer sign-off for control tests
- Full audit trail
- Organisation and user administration
- Framework mapping, evidence freshness, control-health reporting and audit-pack export
- In-app user manual
- Responsive original Revolt-X Control interface
- CSP, restricted CORS, verified database TLS and API/login rate limits

## Live direct connector adapters

The platform never marks a connector **Connected** until the provider validates the supplied credential.

- GitHub
- Microsoft Entra ID
- Microsoft 365
- Jira
- ServiceNow
- Splunk
- Tenable
- CrowdStrike Falcon

Connector secrets are encrypted at rest with a dedicated application encryption key. Provider syncs create structured evidence with SHA-256 hashes and can create control findings when defined exceptions are detected.

Other source types remain visible in the connector catalogue for the planned direct adapter or private-network **Revolt-X Connector Agent**. Private network URLs are intentionally blocked from the public cloud connector path.

## Core assurance lifecycle

1. Define and assign a control.
2. Collect and review source evidence.
3. Test the control and document the procedure.
4. Raise and assign findings for exceptions.
5. Remediate and retest.
6. Close only after validated resolution.
7. Retain the audit trail and export assurance packs.

## Local setup

1. Copy `.env.example` to `.env`.
2. Create PostgreSQL and set `DATABASE_URL`.
3. Set independent strong values for `JWT_SECRET` and `INTEGRATION_ENCRYPTION_KEY`.
4. Set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ALLOWED_ORIGINS`.
5. Run `npm install`.
6. Run `npm run dev`.

The application initializes its schema and seeds the IT control and connector catalogue on an empty organisation.

## Deployment expectations

Production requires HTTPS, verified PostgreSQL TLS, an origin allow-list, protected secrets, and a dedicated database. The application performs an authenticated startup smoke test that validates core read paths plus evidence upload, SHA-256 verification, Test Control and reviewer sign-off, then removes the temporary validation records.
