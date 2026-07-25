# Troubleshooting 502 Bad Gateway Error

If you're getting a 502 Bad Gateway error, follow these steps:

## 1. Check if Backend Server is Running

```bash
# Check if the server process is running
ps aux | grep node
# or
pm2 list  # if using PM2
# or
systemctl status your-backend-service  # if using systemd
```

## 2. Check Backend Logs

Look for errors in your backend logs:

```bash
# If running with npm
npm run dev  # Check console output

# If using PM2
pm2 logs

# If using systemd
journalctl -u your-backend-service -f
```

## 3. Common Issues

### Issue: WAF Agent Credentials Not Set

**Symptom:** Server starts but WAF toggle requests fail with 502, and the error
reads `... is remote (...), so WAF_AGENT_PRIVATE_KEY and WAF_AGENT_AUTH_TOKEN
must be set in .env`

**Cause:** `WAF_AGENT_URL` points at a public IP or domain. Credentials are only
optional when the agent runs on localhost or a private network address.

**Solutions**, pick whichever matches your deployment:

1. **The agent really is remote** — set both credentials:

   ```env
   WAF_AGENT_AUTH_TOKEN="a-long-random-token"
   WAF_AGENT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
   (paste your key here)
   -----END PRIVATE KEY-----"
   ```

2. **The agent is actually on this machine, your LAN, or behind a tunnel** —
   point the URL at its private address, and no credentials are needed:

   ```env
   WAF_AGENT_URL="http://localhost:8080"     # same host / SSH forward
   WAF_AGENT_URL="http://10.8.0.3:8080"      # LAN or WireGuard peer
   WAF_AGENT_URL="http://100.101.102.103:8080"  # Tailscale
   ```

There is no third option — no environment flag marks a public URL as trusted.

**Note:** The server always starts; only the agent calls fail. Check the startup
log line beginning with 🔒, 🔓, or ⚠️ to see which mode is active.

### Issue: Invalid Private Key Format

**Symptom:** Server crashes on startup or when importing WAF agent service

**Solution:** 
- Make sure the key includes `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----`
- If pasting from a file, ensure newlines are preserved or use `\n` in the .env file
- Try wrapping in quotes in .env file

### Issue: Backend Server Not Running

**Symptom:** 502 error immediately, no response

**Solution:**
```bash
# Start the server
cd modsecurity-back-end
npm run dev

# Or if using production build
npm run build
npm start
```

### Issue: Port Already in Use

**Symptom:** Server fails to start, port error

**Solution:**
```bash
# Check what's using the port (default 3001)
lsof -i :3001
# or
netstat -tulpn | grep 3001

# Kill the process or change PORT in .env
```

## 4. Test Backend Health

```bash
# Test if backend is responding
curl http://localhost:3001/health

# Should return:
# {"status":"ok","timestamp":"..."}
```

## 5. Check Environment Variables

Make sure all required environment variables are set:

```bash
# Check .env file exists
ls -la modsecurity-back-end/.env

# Verify key variables are set (don't show actual values)
grep -E "^(WAF_AGENT_URL|WAF_AGENT_PRIVATE_KEY|DATABASE_URL|SUPABASE)" modsecurity-back-end/.env
```

## 6. Test WAF Agent Service Directly

If the server starts but WAF calls fail, test the agent service:

```typescript
// In a Node.js REPL or test script
import { wafAgentService } from './src/services/wafAgent';

// Check if key is loaded
console.log('Service initialized:', wafAgentService);

// Try a test call (will fail if key not set, but won't crash)
try {
  await wafAgentService.toggleWAF('test.example.com', true);
} catch (error) {
  console.log('Expected error (key not set):', error.message);
}
```

## 7. Quick Fix: Disable WAF Agent Temporarily

If you need the server to run without WAF agent:

1. Comment out the WAF agent import in `domain-waf.routes.ts`:
```typescript
// import { wafAgentService } from "../services/wafAgent";
```

2. Comment out agent calls in the toggle endpoints

3. Restart server

**Note:** This will allow database updates but won't call the WAF agent.

## 8. Check Network/Firewall

If the backend is on a different server:

```bash
# Test if backend is accessible
curl http://your-backend-ip:3001/health

# Check firewall rules
sudo ufw status
# or
sudo iptables -L
```

## Still Having Issues?

1. Check the exact error message in backend logs
2. Verify Node.js version: `node --version` (should be 18+)
3. Reinstall dependencies: `rm -rf node_modules && npm install`
4. Check TypeScript compilation: `npm run build` (look for errors)




