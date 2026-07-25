/**
 * Agent endpoint classification.
 *
 * The WAF/Geo agent either runs on this same machine or is reached over a
 * network. Credentials only buy security in the second case: a request to
 * loopback never touches a network interface, so demanding an RSA signing key
 * and a bearer token there is setup friction with no payoff.
 *
 * This module answers one question — "is this agent URL loopback?" — so the
 * agent services can relax or enforce credential requirements accordingly.
 *
 * Why loopback and not the whole private network
 * ----------------------------------------------
 * The agent applies the mirror-image rule (see the waf-agent repo,
 * src/security.py::is_trusted_local_request) and trusts only callers whose peer
 * address is loopback. The two definitions MUST match: if this side skipped
 * credentials for, say, a 10.x agent, the agent would answer 403 and the
 * operator would face a backend claiming "local, no credentials needed" against
 * an agent demanding them. A LAN is also not automatically trustworthy — the
 * agent can disable the firewall, so "anyone on the subnet" is too wide a
 * blast radius to grant silently.
 */

export interface AgentEndpoint {
  /** Normalized base URL with any trailing slash removed. */
  url: string;
  /** Hostname with IPv6 brackets stripped, lowercased. */
  hostname: string;
  /** URL protocol, including the trailing colon (e.g. "http:"). */
  protocol: string;
  /** True when the host is a loopback address on this machine. */
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
 * Only the .localhost suffix is reserved by RFC 6761 to always resolve to the
 * loopback interface. Other private-use suffixes (.local, .internal,
 * .home.arpa) name other machines on the network, so they are NOT loopback.
 */
const LOOPBACK_HOSTNAME_SUFFIXES = [".localhost"];

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
 * Classify an IPv4 address as loopback. Only 127.0.0.0/8 qualifies — private
 * ranges such as 10.x or 192.168.x name a different machine and must present
 * credentials.
 */
function classifyIPv4(octets: number[]): string | null {
  if (octets[0] === 127) return "loopback address (127.0.0.0/8)";
  return null;
}

/**
 * Classify an IPv6 address as loopback. Handles the IPv4-mapped form
 * (::ffff:127.0.0.1) by delegating to the IPv4 classifier.
 */
function classifyIPv6(hostname: string): string | null {
  const address = hostname.toLowerCase();

  if (address === "::1") return "IPv6 loopback address (::1)";

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

  return null;
}

/**
 * Decide whether a hostname refers to this same machine. Returns the reason
 * when it is loopback, or null for anything reached over a network.
 */
function classifyHostname(hostname: string): string | null {
  const host = hostname.toLowerCase();

  if (LOOPBACK_HOSTNAMES.has(host)) return `loopback hostname ("${host}")`;

  for (const suffix of LOOPBACK_HOSTNAME_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return `loopback-reserved domain suffix ("${suffix}")`;
    }
  }

  const octets = parseIPv4(host);
  if (octets) return classifyIPv4(octets);

  // A hostname reached as an IPv6 literal never contains dots; anything with a
  // colon at this point is an address rather than a DNS name.
  if (host.includes(":")) return classifyIPv6(host);

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
    reason: localReason ?? `"${hostname}" is reached over a network`,
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
 * An agent reached over an SSH forward is addressed as localhost:PORT and
 * already qualifies. Anything else genuinely crosses a network, and the only
 * thing an override could enable is an unauthenticated agent that can disable
 * the firewall — exactly what this module exists to prevent.
 */
