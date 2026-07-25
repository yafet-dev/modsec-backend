/**
 * Host filtering for logs.
 *
 * A host filter must match the host itself and its subdomains, and nothing
 * else. This was previously a Prisma `contains`, which is a plain substring
 * test, so selecting "gnzabe.com" also matched "notgnzabe.com" and
 * "gnzabe.com.attacker.net", and a short domain like "a.co" matched almost
 * every host. That is why the filter appeared to do nothing.
 */

/** Lowercase, trim, and drop a trailing root dot. */
function canonicalHost(value: string): string {
  return (value ?? "").trim().toLowerCase().replace(/\.+$/, "");
}

/**
 * Prisma condition selecting a host and its subdomains.
 *
 *   "gnzabe.com"         -> gnzabe.com, apiprod.gnzabe.com, a.b.gnzabe.com
 *   "apiprod.gnzabe.com" -> apiprod.gnzabe.com and its own subdomains only
 *
 * Returned as an `OR` group so callers can place it inside an `AND` array
 * alongside other filters; assigning it to `where.OR` directly would collide
 * with the search filter and silently drop one of them.
 */
export function buildHostCondition(hostFilter: string) {
  const host = canonicalHost(hostFilter);

  return {
    OR: [
      { host: { equals: host, mode: "insensitive" as const } },
      { host: { endsWith: `.${host}`, mode: "insensitive" as const } },
    ],
  };
}

/**
 * The same rule in plain JavaScript, for tests and any in-memory filtering.
 */
export function hostMatchesFilter(host: string, hostFilter: string): boolean {
  const target = canonicalHost(host);
  const filter = canonicalHost(hostFilter);

  if (!filter) return true;

  return target === filter || target.endsWith(`.${filter}`);
}
