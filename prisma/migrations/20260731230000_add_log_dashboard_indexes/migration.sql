-- Range-aware dashboard metrics filter by tenant and time. The trailing
-- columns let PostgreSQL cover the attack-origin IP/severity aggregation too.
CREATE INDEX CONCURRENTLY "Log_organizationId_timestamp_clientIp_severity_idx"
ON "Log"("organizationId", "timestamp", "clientIp", "severity");
