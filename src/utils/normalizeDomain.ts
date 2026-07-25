/**
 * Canonicalize a domain before it is sent to the WAF/Geo agent.
 *
 * These rules must match the agent's `normalize_domain` (waf-agent
 * src/domains.py) exactly. Two reasons:
 *
 * 1. The WAF toggle signature covers the string "domain|enabled". If the
 *    backend signs one form and the agent verifies another, the signature
 *    fails and the toggle 401s.
 * 2. The agent derives filenames from the domain, so a value this side
 *    considers valid but the agent rejects surfaces as a confusing 400.
 */

/** Matches a domain or subdomain; mirrors DOMAIN_RE in the agent. */
const DOMAIN_RE =
  /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/**
 * Lowercase, trim, and drop a trailing root dot.
 *
 * Does not validate — use `isValidDomain` for that, or `assertValidDomain`
 * when an invalid value should be rejected outright.
 */
export function normalizeDomain(domain: string): string {
  return (domain ?? "").trim().toLowerCase().replace(/\.+$/, "");
}

/** True when the value is a well-formed domain or subdomain. */
export function isValidDomain(domain: string): boolean {
  return DOMAIN_RE.test(normalizeDomain(domain));
}

/**
 * Normalize and validate, throwing a descriptive Error when the value is not a
 * plain domain. Rejects path separators, "..", wildcards, and bare
 * single-label names, matching the agent.
 */
export function assertValidDomain(domain: string): string {
  const normalized = normalizeDomain(domain);

  if (!DOMAIN_RE.test(normalized)) {
    throw new Error(
      `Invalid domain "${domain}". Expected a domain or subdomain such as ` +
        `"example.com" or "waf.example.com".`
    );
  }

  return normalized;
}
