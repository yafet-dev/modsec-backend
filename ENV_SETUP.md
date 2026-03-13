# Environment Variables Setup

## Required Environment Variables

### Database
```env
DATABASE_URL=postgresql://...
DIRECT_URL=postgresql://...
```

### Supabase
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

### WAF Agent & Geo Agent
Since geo endpoints are now integrated into the waf-agent service (port 8080), you can use:

```env
# WAF Agent URL (used for both WAF and Geo endpoints)
WAF_AGENT_URL=http://localhost:8080

# Optional: Geo Agent URL (defaults to WAF_AGENT_URL if not set)
# GEO_AGENT_URL=http://localhost:8080

# Auth token (shared for both services)
WAF_AGENT_AUTH_TOKEN=your-token-here
# GEO_AGENT_AUTH_TOKEN=your-token-here  # Optional, defaults to WAF_AGENT_AUTH_TOKEN
```

### Server
```env
PORT=3001
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
```

## Quick Setup

1. Copy `.env.example` to `.env` (if exists)
2. Update the values above
3. Make sure `WAF_AGENT_URL` points to port 8080 (where waf-agent runs)
4. Restart your backend server

## Notes

- **WAF Agent** runs on port 8080 and handles both WAF and Geo endpoints
- **Geo endpoints** are at `/v1/geo/*` on the same service
- If `GEO_AGENT_URL` is not set, it automatically uses `WAF_AGENT_URL`
- Both services use the same auth token (`WAF_AGENT_AUTH_TOKEN`)
