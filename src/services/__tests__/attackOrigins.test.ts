import assert from "node:assert/strict";
import { test } from "node:test";
import type { IPLocation } from "../../utils/ipGeolocation";
import {
  aggregateAttackOrigins,
  type GroupedAttackOriginRow,
} from "../attackOrigins";

test("origins use grouped weights, distinct IP counts, highest severity, and descending totals", () => {
  const rows: GroupedAttackOriginRow[] = [
    { clientIp: "8.8.8.8", severity: "LOW", _count: { _all: 125 } },
    { clientIp: "8.8.8.8", severity: "CRITICAL", _count: { _all: 10 } },
    { clientIp: "8.8.4.4", severity: "medium", _count: { _all: 35 } },
    { clientIp: "1.1.1.1", severity: "LOW", _count: { _all: 240 } },
    { clientIp: "9.9.9.9", severity: "MEDIUM", _count: { _all: 20 } },
    { clientIp: "192.168.1.20", severity: "CRITICAL", _count: { _all: 5_000 } },
    { clientIp: "203.0.113.99", severity: "HIGH", _count: { _all: 5_000 } },
    { clientIp: "   ", severity: "HIGH", _count: { _all: 5_000 } },
  ];
  const locations = new Map<string, IPLocation>([
    ["8.8.8.8", { country: "United States", countryCode: "US", lat: 37.75, lng: -97.82 }],
    ["8.8.4.4", { country: "United States", countryCode: "US", lat: 37.4, lng: -122.1 }],
    ["1.1.1.1", { country: "Australia", countryCode: "AU", lat: -33.49, lng: 143.21 }],
    ["9.9.9.9", { country: "Germany", countryCode: "DE", lat: 51.17, lng: 10.45 }],
    ["192.168.1.20", { country: "Local", lat: 0, lng: 0 }],
  ]);

  const origins = aggregateAttackOrigins(rows, locations);

  assert.deepEqual(origins, [
    {
      ip: "1.1.1.1",
      country: "Australia",
      countryCode: "AU",
      lat: -33.49,
      lng: 143.21,
      count: 240,
      ipCount: 1,
      severity: "low",
    },
    {
      ip: "8.8.8.8",
      country: "United States",
      countryCode: "US",
      lat: 37.75,
      lng: -97.82,
      count: 170,
      ipCount: 2,
      severity: "high",
    },
    {
      ip: "9.9.9.9",
      country: "Germany",
      countryCode: "DE",
      lat: 51.17,
      lng: 10.45,
      count: 20,
      ipCount: 1,
      severity: "medium",
    },
  ]);

  assert.equal(
    origins.some((origin) => origin.ip === "192.168.1.20"),
    false,
    "private/local addresses must not become map markers"
  );
  assert.equal(
    origins.some((origin) => origin.ip === "203.0.113.99"),
    false,
    "addresses without a location must be excluded"
  );
});
