export interface ModsecLandingSummaryRow {
  id: bigint;
  time: Date;
  data: unknown;
  processed: boolean | null;
}

export interface PendingHostSummary {
  host: string | null;
  pendingCount: number;
  oldestPendingAt: Date;
}

export interface PendingLandingSnapshot {
  hosts: PendingHostSummary[];
  checkedAt: Date;
}

export type PendingLandingPageLoader = (
  afterId: bigint | undefined,
  take: number
) => Promise<ModsecLandingSummaryRow[]>;

interface JsonObject {
  [key: string]: unknown;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseEmbeddedJson(value: string): unknown {
  let candidate: unknown = value;

  // Fluent Bit may wrap the transaction JSON in a JSON string. Unwrap at
  // most twice so malformed or adversarial values cannot cause an endless
  // parse loop.
  for (let depth = 0; depth < 2 && typeof candidate === "string"; depth++) {
    const text = candidate.trim();
    if (!text) return null;

    try {
      candidate = JSON.parse(text);
      continue;
    } catch {
      // Match the processor's legacy fallback for quoted/escaped audit JSON.
      const withoutQuotes =
        (text.startsWith('"') && text.endsWith('"')) ||
        (text.startsWith("'") && text.endsWith("'"))
          ? text.slice(1, -1)
          : text;
      const unescaped = withoutQuotes
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, "\\");

      if (unescaped === text) return null;

      try {
        candidate = JSON.parse(unescaped);
      } catch {
        return null;
      }
    }
  }

  return candidate;
}

/**
 * Return a ModSecurity transaction from any landing wrapper currently
 * accepted by the processor. Invalid payloads return null and never throw.
 */
export function parseModsecLandingTransaction(data: unknown): JsonObject | null {
  let candidate: unknown = data;

  if (typeof candidate === "string") {
    candidate = parseEmbeddedJson(candidate);
  }

  if (!isJsonObject(candidate)) return null;

  if (typeof candidate.raw === "string") {
    candidate = parseEmbeddedJson(candidate.raw);
  } else if (typeof candidate.data === "string") {
    candidate = parseEmbeddedJson(candidate.data);
  } else if (isJsonObject(candidate.transaction)) {
    return candidate.transaction;
  } else if (isJsonObject(candidate.data)) {
    candidate = candidate.data;
  }

  if (!isJsonObject(candidate)) return null;

  if (isJsonObject(candidate.transaction)) {
    return candidate.transaction;
  }

  // Some producers store the transaction itself rather than wrapping it in a
  // top-level `transaction` property.
  return isJsonObject(candidate.request) ? candidate : null;
}

/** Canonicalize a request hostname without broadening it to parent domains. */
export function normalizeModsecHostname(value: unknown): string | null {
  if (typeof value !== "string") return null;

  let host = value.trim();
  if (!host) return null;

  if (host.startsWith("[")) {
    const bracketedIpv6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(host);
    if (!bracketedIpv6) return null;
    if (
      bracketedIpv6[2] !== undefined &&
      Number.parseInt(bracketedIpv6[2], 10) > 65_535
    ) {
      return null;
    }
    host = bracketedIpv6[1];
  } else {
    const colonCount = (host.match(/:/g) ?? []).length;
    if (colonCount === 1) {
      const separator = host.lastIndexOf(":");
      const port = host.slice(separator + 1);
      if (!/^\d+$/.test(port) || Number.parseInt(port, 10) > 65_535) {
        return null;
      }
      host = host.slice(0, separator);
    }
    // More than one colon is an unbracketed IPv6 literal and has no port.
  }

  host = host.trim().toLowerCase().replace(/\.+$/, "");
  if (!host || /[\s/\\?#@]/.test(host)) return null;

  return host;
}

/** Extract hostname first, then a case-insensitive Host header fallback. */
export function extractModsecLandingHost(data: unknown): string | null {
  const transaction = parseModsecLandingTransaction(data);
  if (!transaction || !isJsonObject(transaction.request)) return null;

  const request = transaction.request;
  const hostname = normalizeModsecHostname(request.hostname);
  if (hostname) return hostname;

  if (!isJsonObject(request.headers)) return null;

  for (const [name, value] of Object.entries(request.headers)) {
    if (name.toLowerCase() !== "host") continue;
    const headerHost = normalizeModsecHostname(value);
    if (headerHost) return headerHost;
  }

  return null;
}

function mergePendingRows(
  summaries: Map<string | null, PendingHostSummary>,
  rows: readonly ModsecLandingSummaryRow[]
): void {
  for (const row of rows) {
    // Deliberately exclude null. The production processor also selects with
    // `where: { processed: false }`, and the user-facing number must describe
    // that exact queue rather than every non-true legacy value.
    if (row.processed !== false) continue;

    const host = extractModsecLandingHost(row.data);
    const current = summaries.get(host);

    if (!current) {
      summaries.set(host, {
        host,
        pendingCount: 1,
        oldestPendingAt: row.time,
      });
      continue;
    }

    current.pendingCount++;
    if (row.time.getTime() < current.oldestPendingAt.getTime()) {
      current.oldestPendingAt = row.time;
    }
  }
}

function sortedSummaries(
  summaries: Map<string | null, PendingHostSummary>
): PendingHostSummary[] {
  return [...summaries.values()].sort((left, right) => {
    if (left.host === null) return right.host === null ? 0 : 1;
    if (right.host === null) return -1;
    return left.host.localeCompare(right.host);
  });
}

/** Pure grouping helper used by tests and by each scanner page. */
export function summarizePendingLandingRows(
  rows: readonly ModsecLandingSummaryRow[]
): PendingHostSummary[] {
  const summaries = new Map<string | null, PendingHostSummary>();
  mergePendingRows(summaries, rows);
  return sortedSummaries(summaries);
}

/**
 * Scan pending rows by monotonically increasing bigint ID. This remains
 * memory-bounded per database page while retaining only compact host groups.
 */
export async function scanPendingLandingRows(
  loadPage: PendingLandingPageLoader,
  options: { pageSize?: number; checkedAt?: Date } = {}
): Promise<PendingLandingSnapshot> {
  const pageSize = Math.max(1, Math.min(options.pageSize ?? 500, 2_000));
  const summaries = new Map<string | null, PendingHostSummary>();
  let afterId: bigint | undefined;

  while (true) {
    const rows = await loadPage(afterId, pageSize);
    if (rows.length === 0) break;

    mergePendingRows(summaries, rows);

    const nextId = rows[rows.length - 1].id;
    if (afterId !== undefined && nextId <= afterId) {
      throw new Error("Pending landing scan did not advance its keyset cursor");
    }
    afterId = nextId;

    if (rows.length < pageSize) break;
  }

  return {
    hosts: sortedSummaries(summaries),
    checkedAt: options.checkedAt ?? new Date(),
  };
}

/** Select a compact all-host or exact-host result from the cached snapshot. */
export function selectPendingLandingSummary(
  snapshot: PendingLandingSnapshot,
  options: {
    allowedHosts: ReadonlySet<string> | null;
    host?: string;
  }
): { pendingCount: number; oldestPendingAt: Date | null } {
  let pendingCount = 0;
  let oldestPendingAt: Date | null = null;

  for (const summary of snapshot.hosts) {
    if (options.host !== undefined && summary.host !== options.host) continue;
    if (
      options.allowedHosts !== null &&
      (summary.host === null || !options.allowedHosts.has(summary.host))
    ) {
      continue;
    }

    pendingCount += summary.pendingCount;
    if (
      oldestPendingAt === null ||
      summary.oldestPendingAt.getTime() < oldestPendingAt.getTime()
    ) {
      oldestPendingAt = summary.oldestPendingAt;
    }
  }

  return { pendingCount, oldestPendingAt };
}
