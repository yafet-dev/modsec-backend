import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildLogAnalyticsResponse,
  calculateThreatLevel,
  getAnalyticsWindow,
  parseAnalyticsRange,
  type AnalyticsAggregateRow,
  type AnalyticsRange,
} from "../logAnalytics";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

function row(
  bucketIndex: number,
  attacks: number | bigint,
  blocked: number | bigint,
  severities: Partial<
    Pick<AnalyticsAggregateRow, "critical" | "high" | "medium" | "low">
  > = {}
): AnalyticsAggregateRow {
  return {
    bucketIndex,
    attacks,
    blocked,
    critical: severities.critical ?? 0,
    high: severities.high ?? 0,
    medium: severities.medium ?? 0,
    low: severities.low ?? 0,
  };
}

test("every analytics range has the expected bucket count and duration", () => {
  const now = new Date("2026-07-31T12:34:56.789Z");
  const cases: Array<{
    range: AnalyticsRange;
    bucketCount: number;
    bucketSizeMs: number;
    durationMs: number;
  }> = [
    {
      range: "24h",
      bucketCount: 24,
      bucketSizeMs: HOUR_MS,
      durationMs: DAY_MS,
    },
    {
      range: "7d",
      bucketCount: 7,
      bucketSizeMs: DAY_MS,
      durationMs: 7 * DAY_MS,
    },
    {
      range: "30d",
      bucketCount: 30,
      bucketSizeMs: DAY_MS,
      durationMs: 30 * DAY_MS,
    },
    {
      range: "3m",
      bucketCount: 13,
      bucketSizeMs:
        (now.getTime() - new Date("2026-04-30T12:34:56.789Z").getTime()) /
        13,
      durationMs:
        now.getTime() - new Date("2026-04-30T12:34:56.789Z").getTime(),
    },
  ];

  for (const expected of cases) {
    const window = getAnalyticsWindow(expected.range, now);

    assert.equal(window.end.getTime(), now.getTime(), `${expected.range} end`);
    assert.equal(
      window.start.getTime(),
      now.getTime() - expected.durationMs,
      `${expected.range} start`
    );
    assert.equal(
      window.bucketCount,
      expected.bucketCount,
      `${expected.range} bucket count`
    );
    assert.equal(
      window.bucketSizeMs,
      expected.bucketSizeMs,
      `${expected.range} bucket size`
    );
  }
});

test("three months uses calendar subtraction and clamps month-end dates", () => {
  const leapYear = getAnalyticsWindow(
    "3m",
    new Date("2024-05-31T08:15:00.000Z")
  );
  const ordinaryYear = getAnalyticsWindow(
    "3m",
    new Date("2026-05-31T08:15:00.000Z")
  );

  assert.equal(leapYear.start.toISOString(), "2024-02-29T08:15:00.000Z");
  assert.equal(ordinaryYear.start.toISOString(), "2026-02-28T08:15:00.000Z");
});

test("only supported range values are accepted", () => {
  assert.equal(parseAnalyticsRange("24h"), "24h");
  assert.equal(parseAnalyticsRange("7d"), "7d");
  assert.equal(parseAnalyticsRange("30d"), "30d");
  assert.equal(parseAnalyticsRange("3m"), "3m");
  assert.equal(parseAnalyticsRange("1y"), "24h");
  assert.equal(parseAnalyticsRange(undefined), "24h");
});

test("missing buckets are zero-filled with evenly spaced timestamps", () => {
  const window = getAnalyticsWindow(
    "7d",
    new Date("2026-07-31T00:00:00.000Z")
  );
  const response = buildLogAnalyticsResponse("7d", window, [
    row(2, 9, 4, { high: 1, low: 8 }),
    row(5, 3, 0, { low: 3 }),
  ]);

  assert.equal(response.series.length, 7);
  assert.deepEqual(
    response.series.map(({ attacks, blocked, allowed }) => ({
      attacks,
      blocked,
      allowed,
    })),
    [
      { attacks: 0, blocked: 0, allowed: 0 },
      { attacks: 0, blocked: 0, allowed: 0 },
      { attacks: 9, blocked: 4, allowed: 5 },
      { attacks: 0, blocked: 0, allowed: 0 },
      { attacks: 0, blocked: 0, allowed: 0 },
      { attacks: 3, blocked: 0, allowed: 3 },
      { attacks: 0, blocked: 0, allowed: 0 },
    ]
  );

  for (let index = 0; index < response.series.length; index++) {
    assert.equal(
      response.series[index].timestamp,
      new Date(window.start.getTime() + index * DAY_MS).toISOString()
    );
  }
});

test("database weights are preserved above 100 and blocked plus allowed equals attacks", () => {
  const window = getAnalyticsWindow(
    "24h",
    new Date("2026-07-31T12:00:00.000Z")
  );
  const response = buildLogAnalyticsResponse("24h", window, [
    row(0, 125n, 25n, { low: 125n }),
    row(1, 80n, 20n, { low: 80n }),
  ]);

  assert.equal(response.summary.totalRequests, 205);
  assert.equal(response.summary.blockedAttacks, 45);
  assert.equal(response.summary.allowedRequests, 160);
  assert.equal(response.summary.topRule, null);
  assert.equal(response.series[0].allowed, 100);
  assert.equal(response.series[1].allowed, 60);

  for (const point of response.series) {
    assert.equal(
      point.blocked + point.allowed,
      point.attacks,
      `identity failed at ${point.timestamp}`
    );
  }
});

test("invalid bucket rows cannot affect the series, totals, or threat level", () => {
  const window = getAnalyticsWindow(
    "7d",
    new Date("2026-07-31T00:00:00.000Z")
  );
  const response = buildLogAnalyticsResponse("7d", window, [
    row(0, 3, 2, { low: 3 }),
    row(-1, 1_000, 1_000, { critical: 1_000 }),
    row(7, 1_000, 1_000, { critical: 1_000 }),
    row(1.5, 1_000, 1_000, { critical: 1_000 }),
  ]);

  assert.equal(response.summary.totalRequests, 3);
  assert.equal(response.summary.blockedAttacks, 2);
  assert.equal(response.summary.allowedRequests, 1);
  assert.equal(response.summary.threatLevel, "Low");
  assert.deepEqual(response.series[0], {
    timestamp: window.start.toISOString(),
    attacks: 3,
    blocked: 2,
    allowed: 1,
  });
  assert.equal(
    response.series.slice(1).every((point) => point.attacks === 0),
    true
  );
});

test("empty analytics defaults allowed requests to zero and top rule to null", () => {
  const window = getAnalyticsWindow(
    "24h",
    new Date("2026-07-31T12:00:00.000Z")
  );
  const response = buildLogAnalyticsResponse("24h", window, []);

  assert.deepEqual(response.summary, {
    totalRequests: 0,
    blockedAttacks: 0,
    allowedRequests: 0,
    threatLevel: "Low",
    topRule: null,
  });
});

test("analytics includes the supplied top rule in its summary", () => {
  const window = getAnalyticsWindow(
    "24h",
    new Date("2026-07-31T12:00:00.000Z")
  );
  const topRule = {
    ruleId: "942100",
    ruleName: "SQL Injection Attack Detected",
    count: 37,
  };
  const response = buildLogAnalyticsResponse(
    "24h",
    window,
    [row(0, 10, 4, { high: 2, low: 8 })],
    topRule
  );

  assert.equal(response.summary.allowedRequests, 6);
  assert.deepEqual(response.summary.topRule, topRule);
});

test("threat levels honor simple, compound, and exact boundary thresholds", () => {
  const cases: Array<{
    name: string;
    counts: Parameters<typeof calculateThreatLevel>[0];
    expected: ReturnType<typeof calculateThreatLevel>;
  }> = [
    {
      name: "no traffic",
      counts: { total: 0, critical: 50, high: 50, medium: 50 },
      expected: "Low",
    },
    {
      name: "ordinary low traffic",
      counts: { total: 100, critical: 0, high: 5, medium: 15 },
      expected: "Low",
    },
    {
      name: "critical above ten percent",
      counts: { total: 100, critical: 11, high: 0, medium: 0 },
      expected: "Critical",
    },
    {
      name: "critical compound threshold",
      counts: { total: 100, critical: 6, high: 21, medium: 0 },
      expected: "Critical",
    },
    {
      name: "high above fifteen percent",
      counts: { total: 100, critical: 0, high: 16, medium: 0 },
      expected: "High",
    },
    {
      name: "high compound threshold",
      counts: { total: 100, critical: 0, high: 11, medium: 31 },
      expected: "High",
    },
    {
      name: "medium above twenty-five percent",
      counts: { total: 100, critical: 0, high: 0, medium: 26 },
      expected: "Medium",
    },
    {
      name: "medium compound threshold",
      counts: { total: 100, critical: 0, high: 6, medium: 16 },
      expected: "Medium",
    },
    {
      name: "exact critical threshold is not above it",
      counts: { total: 100, critical: 10, high: 0, medium: 0 },
      expected: "Low",
    },
    {
      name: "exact high threshold is not above it",
      counts: { total: 100, critical: 0, high: 15, medium: 0 },
      expected: "Low",
    },
    {
      name: "exact medium threshold is not above it",
      counts: { total: 100, critical: 0, high: 0, medium: 25 },
      expected: "Low",
    },
  ];

  for (const scenario of cases) {
    assert.equal(
      calculateThreatLevel(scenario.counts),
      scenario.expected,
      scenario.name
    );
  }
});
