/**
 * Agent endpoint classification.
 *
 * The WAF/Geo agent either runs on the same host (or inside the same private
 * network) as this backend, or it is reached across the public internet.
 * Credentials only buy security in the second case: traffic to a loopback or
 * RFC1918 address never leaves the trusted network, so demanding an RSA signing
 * key and a bearer token there is setup friction with no payoff.
 *
 * This module answers one question — "is this agent URL local?" — so the agent
 * services can relax or enforce credential requirements accordingly.
 */

export interface AgentEndpoint {
  /** Normalized base URL with any trailing slash removed. */
  url: string;
  /** Hostname with IPv6 brackets stripped, lowercased. */
  hostname: string;
  /** URL protocol, including the trailing colon (e.g. "http:"). */
  protocol: string;
  /** True when the host is loopback, link-local, or inside a private range. */
  isLocal: boolean;
  /** Human-readable justification, surfaced in startup logs and errors. */
  reason: string;
}

/** Hostnames that always resolve back to the local machine. */
const LOOPBACK_HOSTNAMES = new Set([
  "localhost",
  "ip6-localhost",
  "ip6-loopback",
]);

/**
 * Suffixes reserved for names that cannot be resolved on the public internet:
 * mDNS (.local), cloud-internal DNS (.internal), and RFC 8375 (.home.arpa).
 */
const PRIVATE_HOSTNAME_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".home.arpa",
];

/**
 * Parse a dotted-quad IPv4 address into its four octets.
 * Returns null for anything that is not a plain IPv4 literal, including
 * shorthand forms ("10.1") and zero-padded octets ("010.0.0.1"), which are
 * ambiguous enough that we would rather treat them as non-local.
 */
function parseIPv4(hostname: string): number[] | null {
  const parts = hostname.split(".");
  if (parts.length !== 4) return null;

  const octets: number[] = [];
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    octets.push(value);
  }

  return octets;
}

/**
 * Classify an IPv4 address as private/local per IANA special-purpose ranges.
 */
function classifyIPv4(octets: number[]): string | null {
  const [a, b] = octets;

  if (a === 0) return "unspecified/this-network address (0.0.0.0/8)";
  if (a === 10) return "private network address (10.0.0.0/8)";
  if (a === 127) return "loopback address (127.0.0.0/8)";
  if (a === 169 && b === 254) return "link-local address (169.254.0.0/16)";
  if (a === 172 && b >= 16 && b <= 31) {
    return "private network address (172.16.0.0/12)";
  }
  if (a === 192 && b === 168) return "private network address (192.168.0.0/16)";
  // Carrier-grade NAT, also the range Tailscale hands out for its mesh.
  if (a === 100 && b >= 64 && b <= 127) {
    return "carrier-grade NAT / VPN mesh address (100.64.0.0/10)";
  }
  if (a === 198 && (b === 18 || b === 19)) {
    return "benchmarking address (198.18.0.0/15)";
  }

  return null;
}

/**
 * Classify an IPv6 address as private/local. Handles the IPv4-mapped form
 * (::ffff:127.0.0.1) by delegating to the IPv4 classifier.
 */
function classifyIPv6(hostname: string): string | null {
  const address = hostname.toLowerCase();

  if (address === "::1") return "IPv6 loopback address (::1)";
  if (address === "::") return "IPv6 unspecified address (::)";

  // Dotted form, e.g. ::ffff:127.0.0.1
  const dottedMapped = /^::ffff:([0-9.]+)$/.exec(address);
  if (dottedMapped) {
    const octets = parseIPv4(dottedMapped[1]);
    if (octets) {
      const reason = classifyIPv4(octets);
      return reason ? `IPv4-mapped ${reason}` : null;
    }
  }

  // Hex form, e.g. ::ffff:7f00:1 — this is what the WHATWG URL parser
  // normalizes the dotted form into, so it is the shape we usually see.
  const hexMapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
  if (hexMapped) {
    const high = parseInt(hexMapped[1], 16);
    const low = parseInt(hexMapped[2], 16);
    const octets = [high >> 8, high & 0xff, low >> 8, low & 0xff];
    const reason = classifyIPv4(octets);
    return reason ? `IPv4-mapped ${reason}` : null;
  }

  // Unique local addresses: fc00::/7 covers any address whose first byte is
  // 0xfc or 0xfd.
  if (/^f[cd][0-9a-f]{0,2}:/.test(address)) {
    return "IPv6 unique local address (fc00::/7)";
  }

  // Link-local: fe80::/10 covers first byte 0xfe with top two bits of the
  // second nibble clear, i.e. fe8x through febx.
  if (/^fe[89ab][0-9a-f]?:/.test(address)) {
    return "IPv6 link-local address (fe80::/10)";
  }

  return null;
}

/**
 * Decide whether a hostname refers to something on the local machine or the
 * local/private network. Returns the reason when local, or null when the host
 * looks publicly routable.
 */
function classifyHostname(hostname: string): string | null {
  const host = hostname.toLowerCase();

  if (LOOPBACK_HOSTNAMES.has(host)) return `loopback hostname ("${host}")`;

  for (const suffix of PRIVATE_HOSTNAME_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return `private-use domain suffix ("${suffix}")`;
    }
  }

  const octets = parseIPv4(host);
  if (octets) return classifyIPv4(octets);

  // A hostname reached as an IPv6 literal never contains dots; anything with a
  // colon at this point is an address rather than a DNS name.
  if (host.includes(":")) return classifyIPv6(host);

  // A single-label name has no public TLD, so it can only be resolved by local
  // DNS — this is how Docker Compose and Kubernetes service names look.
  if (!host.includes(".")) {
    return `single-label hostname resolved on the local network ("${host}")`;
  }

  return null;
}

/**
 * Normalize a raw environment value: strip the surrounding quotes that .env
 * files commonly leave behind, trim whitespace, and drop a trailing slash so
 * path concatenation never produces a double slash.
 */
export function normalizeEnvValue(value: string | undefined): string {
  return (value ?? "").replace(/^["']|["']$/g, "").trim();
}

/**
 * Resolve an agent base URL into a classified endpoint.
 *
 * Falls back to `fallbackUrl` when the value is blank. An unparseable URL is
 * treated as non-local: we cannot prove it is safe, so we fail closed and let
 * the caller demand credentials.
 */
export function resolveAgentEndpoint(
  rawUrl: string | undefined,
  fallbackUrl: string
): AgentEndpoint {
  const candidate = normalizeEnvValue(rawUrl) || fallbackUrl;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      url: candidate.replace(/\/+$/, ""),
      hostname: "",
      protocol: "",
      isLocal: false,
      reason: `"${candidate}" is not a valid URL, so it is treated as remote`,
    };
  }

  // Node returns IPv6 hostnames wrapped in brackets ("[::1]").
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const localReason = classifyHostname(hostname);

  return {
    url: candidate.replace(/\/+$/, ""),
    hostname,
    protocol: parsed.protocol,
    isLocal: localReason !== null,
    reason: localReason ?? `"${hostname}" is a publicly routable host`,
  };
}

/**
 * Convenience predicate for callers that only need the boolean.
 */
export function isLocalAgentUrl(url: string): boolean {
  return resolveAgentEndpoint(url, url).isLocal;
}

/**
 * There is deliberately no environment flag to bypass this classification.
 *
 * A tunnelled agent (WireGuard, Tailscale, an SSH forward) is always addressed
 * by its private endpoint — 10.x, 100.64.x, or localhost:PORT — so it already
 * classifies as local and needs no override. The only thing an override could
 * enable is talking to a genuinely public agent without credentials, which is
 * exactly what this module exists to prevent.
 */
