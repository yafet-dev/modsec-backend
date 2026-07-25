# WAF Agent Integration Setup

This guide explains how to configure the backend to communicate with the WAF agent.

## Do I Need Keys At All?

**It depends on where the agent runs.** The backend decides automatically from
`WAF_AGENT_URL`:

| `WAF_AGENT_URL` points at | Signing key | Auth token |
| --- | --- | --- |
| Loopback — the same machine | Optional | Optional |
| Anything else, private LAN included | **Required** | **Required** |

Signatures and bearer tokens protect requests crossing a network. If the agent
is on the same box, the request never touches a network interface and the
credentials buy nothing — so the backend skips them and talks to the agent
unauthenticated.

A URL qualifies only when the host is `localhost`, `127.x.x.x`, `::1`,
`::ffff:127.0.0.1`, or a `.localhost` name.

Everything else needs both credentials — and that deliberately **includes
private/LAN addresses** like `10.0.0.5` or a Docker service name, not just
public hosts like `196.188.250.141`. The agent can disable your firewall, so
trusting a whole subnet is too wide a blast radius to grant silently.

Both sides enforce this. The agent trusts a caller only when its peer address is
loopback (`is_trusted_local_request` in `src/security.py`), so the backend and
the agent agree on exactly one credential-free case: both on the same host.

> Credentials are always **used** when configured, loopback or not. The rule
> only governs what is **required**. Set them on a local agent if you want
> requests authenticated anyway.

## Local Setup (agent on the same host)

One line:

```env
WAF_AGENT_URL="http://localhost:8080"
```

At startup you will see:

```
🔓 WAF Agent at http://localhost:8080 is local (loopback hostname ("localhost")). Signing key and auth token are optional.
```

## Remote Setup (agent across the internet)

### How Communication Works

The communication matches `test_toggle.sh` exactly:

- **Backend** has the **PRIVATE key** (to sign requests)
- **Agent** has the **PUBLIC key** (to verify signatures)
- Data format: `domain|enabled` where enabled is lowercase "true" or "false"
- Uses RSA PSS padding with SHA256

### Environment Variables

Add the following environment variables to your `.env` file:

```env
# WAF Agent Configuration
# URL of the WAF agent service (e.g., http://196.188.250.141:8080)
WAF_AGENT_URL="http://196.188.250.141:8080"

# Private key content (PEM format) - paste the entire key here
# This is the PRIVATE key that matches the PUBLIC key on the agent server
# You can get this from /etc/waf-agent/private_key.pem on the WAF agent server
WAF_AGENT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
(paste the entire key content here, including BEGIN/END lines)
-----END PRIVATE KEY-----"

# Shared bearer token the agent expects
WAF_AGENT_AUTH_TOKEN="a-long-random-token"
```

Prefer `https://` for a remote agent. Over plain `http://` the bearer token
crosses the internet in cleartext, and the backend warns about this at startup.

### Agent behind an SSH forward

An SSH forward is the one tunnel that lands on loopback, so it needs no
credentials:

```bash
ssh -L 8080:localhost:8080 user@waf-host
```

```env
WAF_AGENT_URL="http://localhost:8080"
```

WireGuard and Tailscale peers are addressed as `10.x` / `100.64.x`, which are
*not* loopback — those still require credentials on both sides. There is
deliberately no flag to mark a non-loopback URL as trusted.

### Agent behind a reverse proxy

If the agent sits behind nginx or similar, every request arrives from the proxy
and therefore looks like loopback. The agent refuses to treat a request as local
when it carries `X-Forwarded-For`, `X-Real-IP`, or `Forwarded`, but a proxy that
strips those would defeat the check. In that setup, set this on the **agent**:

```env
WAF_AGENT_STRICT_AUTH=true
```

That forces credentials for every caller, loopback included. It only ever
tightens the policy.

## Setting Up the Private Key

1. **Get the private key from the WAF agent server:**

   ```bash
   # On the WAF agent server (196.188.250.141)
   cat /etc/waf-agent/private_key.pem
   ```

2. **Copy the entire key content (including BEGIN/END lines) and paste it in your `.env` file:**

   ```env
   WAF_AGENT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
   MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
   (paste all lines here)
   -----END PRIVATE KEY-----"
   ```

   **Important:**

   - Keep the quotes around the key
   - Include the `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----` lines
   - You can use multi-line format or single-line (the service handles both)

## How It Works

1. When a user toggles WAF status for a domain via the API:

   - The backend first calls the WAF agent at `WAF_AGENT_URL/waf/toggle`
   - The request is signed using the private key
   - The agent verifies the signature and updates the nginx configuration
   - Only if the agent returns success, the backend updates the database

2. **Security:**
   - All requests to the agent are signed with RSA signatures
   - The agent verifies signatures using the corresponding public key
   - This ensures only authorized requests can modify nginx configurations

## Testing

After setting up, test the integration:

1. Make sure the WAF agent is running and accessible
2. Try toggling WAF status for a domain via the API
3. Check the backend logs to see if the agent call was successful
4. Verify the nginx configuration was updated on the WAF server

## Troubleshooting

- **"... is remote (...), so WAF_AGENT_PRIVATE_KEY and WAF_AGENT_AUTH_TOKEN must be set"**:
  `WAF_AGENT_URL` points at a public host. Either supply both credentials, or
  point the URL at the agent's private/tunnel address. There is no bypass flag.
- **"Error loading WAF Agent private key"**: The PEM is malformed. Make sure the
  `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----` lines are included
  and that newlines survived (or are escaped as `\n`) in `.env`.
- **401 / 403 from the agent**: The token does not match, or the agent does not
  hold the public key matching your private key.
- **"WAF agent returned non-OK status"**: Check the agent logs on the WAF server.
- **"Could not reach WAF agent at ..."**: The agent is down or `WAF_AGENT_URL` is
  wrong. The error includes the exact URL that was attempted.
