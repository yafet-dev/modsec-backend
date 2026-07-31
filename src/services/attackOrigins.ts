import type { IPLocation } from "../utils/ipGeolocation";

export type AttackOriginSeverity = "high" | "medium" | "low";

export interface GroupedAttackOriginRow {
  clientIp: string;
  severity: string;
  _count: { _all: number };
}

export interface AttackOrigin {
  ip: string;
  country: string;
  countryCode?: string;
  lat: number;
  lng: number;
  count: number;
  ipCount: number;
  severity: AttackOriginSeverity;
}

const severityRank: Record<AttackOriginSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

function displaySeverity(value: string): AttackOriginSeverity {
  const severity = value.toUpperCase();
  if (severity === "CRITICAL" || severity === "HIGH") return "high";
  if (severity === "MEDIUM") return "medium";
  return "low";
}

/**
 * Turn compact database groups into one weighted marker per country.
 * No individual log rows are materialized here: a group with 20,000 hits is
 * still represented by a single object.
 */
export function aggregateAttackOrigins(
  rows: GroupedAttackOriginRow[],
  locations: Map<string, IPLocation>
): AttackOrigin[] {
  const byCountry = new Map<
    string,
    AttackOrigin & { ips: Set<string> }
  >();

  for (const row of rows) {
    const ip = row.clientIp?.trim();
    if (!ip) continue;

    const location = locations.get(ip);
    if (!location || location.country === "Local") continue;

    const country = location.country || "Unknown";
    const severity = displaySeverity(row.severity);
    const count = Number(row._count._all) || 0;
    const existing = byCountry.get(country);

    if (existing) {
      existing.count += count;
      existing.ips.add(ip);
      existing.ipCount = existing.ips.size;
      if (severityRank[severity] > severityRank[existing.severity]) {
        existing.severity = severity;
      }
      continue;
    }

    byCountry.set(country, {
      ip,
      country,
      countryCode: location.countryCode,
      lat: location.lat,
      lng: location.lng,
      count,
      ipCount: 1,
      severity,
      ips: new Set([ip]),
    });
  }

  return [...byCountry.values()]
    .map(({ ips: _ips, ...origin }) => origin)
    .sort((a, b) => b.count - a.count);
}
