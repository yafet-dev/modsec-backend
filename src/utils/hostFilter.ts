/**
 * Host filtering for logs.
 *
 * Selecting a host shows logs for THAT host and nothing else.
 * apidev.gnzabe.com and apiprod.gnzabe.com are separate options and never
 * appear in each other's results.
 *
 * Two earlier behaviours were both wrong:
 *
 *   - Prisma `contains`, a plain substring test, so "gnzabe.com" matched
 *     notgnzabe.com and gnzabe.com.attacker.net, and "a.co" matched
 *     banana.com.
 *   - exact-or-subdomain, so picking the apex still returned every subdomain
 *     beneath it, which is indistinguishable from no filter when all traffic
 *     lives on subdomains.
 *
 * The host selector is populated from hosts that actually appear in the logs,
 * so every option corresponds to real rows and exact matching cannot produce a
 * surprising empty result.
 */

/** Lowercase, trim, and drop a trailing root dot. */
function canonicalHost(value: string): string {
  return (value ?? "").trim().toLowerCase().replace(/\.+$/, "");
}

/**
 * Prisma condition selecting exactly one host.
 *
 * Returned as an `OR` group of one so callers can place it inside an `AND`
 * array alongside other filters; assigning to `where.OR` directly would
 * collide with the search filter and silently drop one of them.
 */
export function buildHostCondition(hostFilter: string) {
  const host = canonicalHost(hostFilter);

  return {
    OR: [{ host: { equals: host, mode: "insensitive" as const } }],
  };
}

/**
 * The same rule in plain JavaScript, for tests and any in-memory filtering.
 */
export function hostMatchesFilter(host: string, hostFilter: string): boolean {
  const filter = canonicalHost(hostFilter);

  if (!filter) return true;

  return canonicalHost(host) === filter;
}
