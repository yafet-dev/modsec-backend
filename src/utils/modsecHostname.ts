/**
 * Canonicalize a ModSecurity request hostname without broadening it to a
 * parent domain. Keep this behavior aligned with
 * normalize_modsec_source_host() in the source-host migration.
 */
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
