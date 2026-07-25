# WAF Agent Integration Setup

This guide explains how to configure the backend to communicate with the WAF agent.

## Do I Need Keys At All?

**It depends on where the agent runs.** The backend decides automatically from
`WAF_AGENT_URL`:

| `WAF_AGENT_URL` points at | Signing key | Auth token |
| --- | --- | --- |
| Local / private network | Optional | Optional |
| Public IP or public domain | **Required** | **Required** |

Signatures and bearer tokens protect requests crossing an untrusted network. If
the agent is on the same box or the same private LAN, nothing leaves the trusted
network and the credentials buy nothing — so the backend skips them and talks to
the agent unauthenticated.

A URL counts as local when the host is loopback (`localhost`, `127.0.0.1`,
`::1`), an RFC 1918 address (`10.x`, `172.16–31.x`, `192.168.x`), link-local
(`169.254.x`, `fe80::/10`), CGNAT/VPN mesh (`100.64.0.0/10`, used by Tailscale),
IPv6 unique-local (`fc00::/7`), a single-label container service name
(`waf-agent`), or a private-use domain (`.local`, `.internal`, `.home.arpa`).

Anything else — a public IP like `196.188.250.141`, or a domain like
`waf.example.com` — is remote, and both credentials are mandatory. Calls fail
immediately with a clear error instead of going out unsigned over the internet.

> Credentials are always **used** when configured, local or not. The rule only
> governs what is **required**. Set them on a local agent if you want requests
> authenticated anyway.

## Local Setup (agent on the same host or LAN)

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

### Agent behind a tunnel

If the agent is reached through WireGuard, Tailscale, or an SSH forward, use the
tunnel's address rather than the machine's public one:

```env
# WireGuard peer
WAF_AGENT_URL="http://10.8.0.3:8080"
# Tailscale
WAF_AGENT_URL="http://100.101.102.103:8080"
# SSH forward: ssh -L 8080:localhost:8080 user@host
WAF_AGENT_URL="http://localhost:8080"
```

All three classify as local, so no credentials are required — the tunnel already
provides the encryption and authentication that the signature would. There is
deliberately no flag to mark a *public* URL as trusted.

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
