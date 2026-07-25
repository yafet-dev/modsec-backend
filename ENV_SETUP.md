# Backend environment setup

Copy `.env.example` to `.env`, replace every required placeholder, and restart
the backend after changing any value. The backend reads these settings when the
process starts.

```powershell
Copy-Item .env.example .env
npm install
npm run prisma:generate
npm run build
```

Do not commit `.env`. Keep database credentials, `SUPABASE_SERVICE_ROLE_KEY`,
`SMTP_PASS`, agent credentials, seed passwords, and webhook secrets on the
backend only. Never place them in frontend variables or any `NEXT_PUBLIC_*`
value.

## Required core settings

```env
DATABASE_URL="postgresql://postgres:password@localhost:5432/modsec?schema=public"
DIRECT_URL="postgresql://postgres:password@localhost:5432/modsec?schema=public"

SUPABASE_URL="https://your-project.supabase.co"
SUPABASE_ANON_KEY="your-anon-key"
SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"

NODE_ENV="development"
PORT="3001"
FRONTEND_URL="http://localhost:3000"
API_PUBLIC_URL="http://localhost:3001"
PUBLIC_BASE_URL="http://localhost:3001"
```

Supabase remains the identity and session store. It is not the application's
email delivery system: account verification, verification resend, invitations,
forgot-password/reset links, security notifications, and summary reports are
sent by the backend through the SMTP settings below. Do not depend on Supabase
email templates or Supabase SMTP for these application flows.

The service-role key is required for trusted server-side Auth administration,
including creating confirmed seed identities without triggering a Supabase
confirmation email. It must never be sent to the browser.

## Transactional email

Configure a verified sender with your SMTP provider:

```env
SMTP_HOST="smtp.example.com"
SMTP_PORT="587"
SMTP_SECURE="false"
SMTP_USER="smtp-username"
SMTP_PASS="smtp-password"
SMTP_FROM="no-reply@example.com"
SMTP_FROM_NAME="Zergaw Cloud Firewall"
```

`SMTP_HOST`, `SMTP_USER`, and `SMTP_PASS` are required; SMTP authentication is
not optional. `SMTP_PORT` must be an integer from 1 through 65535. Port 587 with
`SMTP_SECURE=false` is the usual STARTTLS configuration. Port 465 normally uses
`SMTP_SECURE=true`; when `SMTP_SECURE` is omitted, the backend infers `true` only
for port 465.

`SMTP_FROM` is the sender used by every backend email, including emails with
inline images. It may be an address or `Display Name <address@example.com>`; an
explicit `SMTP_FROM_NAME` overrides an embedded display name. The address/domain
normally must be verified with the SMTP provider. Existing deployments may
continue using `EMAIL_FROM` as a fallback, but new deployments should use
`SMTP_FROM`. If neither sender-address variable is present, the backend uses the
environment-provided `SMTP_USER` as the sender address.

If the SMTP configuration is missing or invalid, the backend disables email
delivery and logs a startup warning. After updating SMTP values, restart the
backend before testing verification, invitation, and password-reset flows.

## Token lifetimes

```env
PASSWORD_RESET_TOKEN_TTL_MINUTES="60"
INVITATION_TOKEN_TTL_HOURS="72"
```

These positive integer values control the lifetime of backend-issued,
single-use links. Changing them affects newly issued tokens after the backend is
restarted.

## Initial super-admin seed

Set these only when using `npm run seed`:

```env
ADMIN_EMAIL="admin@example.com"
ADMIN_PASSWORD="use-a-strong-unique-password"
ADMIN_FULL_NAME="Super Admin"
# ADMIN_ID="00000000-0000-0000-0000-000000000001"
```

The seed uses the Supabase service-role Admin API. It creates or updates the
confirmed Auth identity without sending a Supabase confirmation email, then
writes the Auth-to-local-user mapping. An existing local user's ID is preserved.
If the Auth operation fails, the seed stops before creating a local database
user. `ADMIN_ID` is used only for a new local user; when omitted, the Auth user
ID is used.

## WAF and Geo agents

Geo endpoints normally share the WAF agent on port 8080:

```env
WAF_AGENT_URL="http://localhost:8080"
WAF_AGENT_AUTH_TOKEN="your-shared-token"
# WAF_AGENT_PRIVATE_KEY="your-PEM-private-key"

# Optional overrides; otherwise the WAF values are used.
# GEO_AGENT_URL="http://localhost:8080"
# GEO_AGENT_AUTH_TOKEN="your-geo-token"
```

Background schedules, summary-report settings, Telegram integration, and the
remaining optional service keys are documented with safe placeholders in
`.env.example`.
