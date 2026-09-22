# Revolt-X Enterprise Control Management

A multi-tenant enterprise controls platform with IT Controls as the first commercial module.

## Current capabilities
- Secure JWT authentication and password hashing
- Organisation-scoped data model
- Role-based permissions
- IT control library
- Control assessments and testing
- Evidence register
- Findings and remediation tracking
- Audit trail
- Dashboard metrics
- Responsive commercial UI
- PostgreSQL persistence

## Planned modules
Cybersecurity Controls, Information Security, Regulatory Compliance, Operational Risk, Business Continuity, Vendor Risk, Internal Audit, Policy Management and Issue Management.

## Local setup
1. Copy `.env.example` to `.env`.
2. Create a PostgreSQL database and set `DATABASE_URL`.
3. Set a strong `JWT_SECRET`, `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
4. Run `npm install`.
5. Run `npm run dev`.

The app automatically initializes the required schema and seeds a starter IT Controls dataset when the organisation is empty.
