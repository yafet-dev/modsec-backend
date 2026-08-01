import assert from "node:assert/strict";
import { test } from "node:test";
import {
  extractModsecLandingHost,
  normalizeModsecHostname,
  parseModsecLandingTransaction,
  scanPendingLandingRows,
  selectPendingLandingSummary,
  summarizePendingLandingRows,
  type ModsecLandingSummaryRow,
} from "../modsecLandingSummary";

function transaction(
  hostname: unknown = "Api.Example.COM.:443",
  headers: Record<string, unknown> = {}
) {
  return {
    transaction: {
      request: {
        hostname,
        headers,
      },
    },
  };
}

function row(
  id: bigint,
  processed: boolean | null,
  time: string,
  data: unknown
): ModsecLandingSummaryRow {
  return { id, processed, time: new Date(time), data };
}

test("landing parser accepts every supported Fluent Bit wrapper", () => {
  const wrapped = transaction();
  const cases: Array<{ name: string; value: unknown }> = [
    { name: "direct transaction", value: wrapped },
    { name: "raw JSON string", value: { raw: JSON.stringify(wrapped) } },
    { name: "data JSON string", value: { data: JSON.stringify(wrapped) } },
    { name: "nested data object", value: { data: wrapped } },
    { name: "bare transaction", value: wrapped.transaction },
    { name: "whole JSON string", value: JSON.stringify(wrapped) },
    {
      name: "double-encoded data string",
      value: { data: JSON.stringify(JSON.stringify(wrapped)) },
    },
  ];

  for (const example of cases) {
    assert.ok(
      parseModsecLandingTransaction(example.value),
      `${example.name} should parse`
    );
    assert.equal(
      extractModsecLandingHost(example.value),
      "api.example.com",
      example.name
    );
  }
});

test("hostname wins and Host header matching is case-insensitive fallback", () => {
  assert.equal(
    extractModsecLandingHost(
      transaction("Primary.Example:443", { Host: "fallback.example:8080" })
    ),
    "primary.example"
  );
  assert.equal(
    extractModsecLandingHost(
      transaction("bad host", { hOsT: "Fallback.Example.:8443" })
    ),
    "fallback.example"
  );
  assert.equal(
    extractModsecLandingHost(transaction("", { host: "lower.example" })),
    "lower.example"
  );
});

test("malformed payloads and transactions without a usable host are unattributed", () => {
  const cases: unknown[] = [
    null,
    [],
    { raw: "not-json" },
    { data: '{"transaction":' },
    { transaction: {} },
    { transaction: { request: { headers: {} } } },
    transaction("bad host", { Host: "also/bad" }),
  ];

  for (const value of cases) {
    assert.equal(extractModsecLandingHost(value), null);
  }
});

test("hostname normalization removes cosmetic differences but not domain levels", () => {
  assert.equal(normalizeModsecHostname(" Example.COM.:443 "), "example.com");
  assert.equal(normalizeModsecHostname("SUB.example.com"), "sub.example.com");
  assert.equal(normalizeModsecHostname("[2001:DB8::1]:443"), "2001:db8::1");
  assert.equal(normalizeModsecHostname("2001:DB8::1"), "2001:db8::1");
  assert.equal(normalizeModsecHostname("example.com:65536"), null);
  assert.equal(normalizeModsecHostname("example.com:not-a-port"), null);
  assert.equal(normalizeModsecHostname("https://example.com"), null);
});

test("summary counts only processed false and tracks oldest per exact host", () => {
  const summaries = summarizePendingLandingRows([
    row(1n, false, "2026-08-01T10:00:00.000Z", transaction("a.example")),
    row(
      2n,
      false,
      "2026-08-01T08:00:00.000Z",
      transaction("", { HOST: "A.EXAMPLE:443" })
    ),
    row(3n, true, "2026-08-01T07:00:00.000Z", transaction("b.example")),
    row(4n, null, "2026-08-01T06:00:00.000Z", transaction("c.example")),
    row(5n, false, "2026-08-01T09:00:00.000Z", { raw: "malformed" }),
  ]);

  assert.deepEqual(summaries, [
    {
      host: "a.example",
      pendingCount: 2,
      oldestPendingAt: new Date("2026-08-01T08:00:00.000Z"),
    },
    {
      host: null,
      pendingCount: 1,
      oldestPendingAt: new Date("2026-08-01T09:00:00.000Z"),
    },
  ]);
});

test("tenant selection is exact while super admin totals include unattributed rows", () => {
  const snapshot = {
    hosts: [
      {
        host: "a.example",
        pendingCount: 3,
        oldestPendingAt: new Date("2026-08-01T08:00:00.000Z"),
      },
      {
        host: "sub.a.example",
        pendingCount: 5,
        oldestPendingAt: new Date("2026-08-01T07:00:00.000Z"),
      },
      {
        host: null,
        pendingCount: 2,
        oldestPendingAt: new Date("2026-08-01T06:00:00.000Z"),
      },
    ],
    checkedAt: new Date("2026-08-01T12:00:00.000Z"),
  };

  assert.deepEqual(
    selectPendingLandingSummary(snapshot, {
      allowedHosts: new Set(["a.example"]),
    }),
    {
      pendingCount: 3,
      oldestPendingAt: new Date("2026-08-01T08:00:00.000Z"),
    }
  );
  assert.deepEqual(
    selectPendingLandingSummary(snapshot, {
      allowedHosts: null,
      host: "sub.a.example",
    }),
    {
      pendingCount: 5,
      oldestPendingAt: new Date("2026-08-01T07:00:00.000Z"),
    }
  );
  assert.deepEqual(
    selectPendingLandingSummary(snapshot, { allowedHosts: null }),
    {
      pendingCount: 10,
      oldestPendingAt: new Date("2026-08-01T06:00:00.000Z"),
    }
  );
});

test("scanner advances by bigint keyset and preserves false-only semantics", async () => {
  const source = [
    row(1n, false, "2026-08-01T10:00:00.000Z", transaction("a.example")),
    row(2n, true, "2026-08-01T09:00:00.000Z", transaction("ignored.example")),
    row(3n, false, "2026-08-01T08:00:00.000Z", transaction("a.example")),
    row(4n, null, "2026-08-01T07:00:00.000Z", transaction("ignored.example")),
    row(5n, false, "2026-08-01T06:00:00.000Z", transaction("b.example")),
  ];
  const cursors: Array<bigint | undefined> = [];
  const checkedAt = new Date("2026-08-01T12:00:00.000Z");

  const snapshot = await scanPendingLandingRows(
    async (afterId, take) => {
      cursors.push(afterId);
      return source
        .filter((item) => afterId === undefined || item.id > afterId)
        .slice(0, take);
    },
    { pageSize: 2, checkedAt }
  );

  assert.deepEqual(cursors, [undefined, 2n, 4n]);
  assert.equal(snapshot.checkedAt, checkedAt);
  assert.deepEqual(
    snapshot.hosts.map(({ host, pendingCount }) => ({ host, pendingCount })),
    [
      { host: "a.example", pendingCount: 2 },
      { host: "b.example", pendingCount: 1 },
    ]
  );
});
