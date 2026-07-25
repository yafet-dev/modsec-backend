-- Logs are filtered and grouped by host (the logs page host selector), but the
-- column had no index, so both were sequential scans over the whole table.
CREATE INDEX "Log_host_idx" ON "Log"("host");
