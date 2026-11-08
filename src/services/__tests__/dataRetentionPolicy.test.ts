import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeModsecHostname } from "../../utils/modsecHostname";
import {
  RETENTION_LIMITS,
  buildRawHostPolicy,
  retentionCutoff,
  retentionDaysFromEnv,
  validateRetentionUpdate,
} from "../dataRetentionPolicy";

const current = { logRetentionDays: 30, rawRetentionDays: 30 };

test("defaults keep one month and cap raw data at three months", () => {
  assert.equal(RETENTION_LIMITS.logs.default, 30);
  assert.equal(RETENTION_LIMITS.raw.default, 30);
  assert.equal(RETENTION_LIMITS.logs.recommendedMax, 90);
  assert.equal(RETENTION_LIMITS.logs.max, 365);
  assert.equal(RETENTION_LIMITS.raw.max, 90);
});

test("accepts values inside the recommended range without acknowledgement", () => {
  const result = validateRetentionUpdate(
    { logRetentionDays: 90, rawRetentionDays: 14 },
    current
  );
  assert.deepEqual(result, {
    ok: true,
    value: { logRetentionDays: 90, rawRetentionDays: 14 },
  });
});

test("requires acknowledgement to raise log retention above three months", () => {
  const rejected = validateRetentionUpdate({ logRetentionDays: 365 }, current);
  assert.equal(rejected.ok, false);
  assert.equal(
    !rejected.ok && rejected.code,
    "STORAGE_WARNING_NOT_ACKNOWLEDGED"
  );

  const accepted = validateRetentionUpdate(
    { logRetentionDays: 365, acknowledgeStorageWarning: true },
    current
  );
  assert.deepEqual(accepted, { ok: true, value: { logRetentionDays: 365 } });
});

test("does not ask again when long retention is unchanged or lowered", () => {
  const saved = { logRetentionDays: 365, rawRetentionDays: 30 };
  assert.equal(
    validateRetentionUpdate({ logRetentionDays: 365, rawRetentionDays: 60 }, saved).ok,
    true
  );
  assert.equal(validateRetentionUpdate({ logRetentionDays: 180 }, saved).ok, true);
  assert.equal(
    validateRetentionUpdate({ logRetentionDays: 200 }, { ...saved, logRetentionDays: 180 }).ok,
    false
  );
});

test("rejects out-of-range, fractional and non-numeric values", () => {
  for (const input of [
    { logRetentionDays: 6 },
    { logRetentionDays: 366 },
    { rawRetentionDays: 91 },
    { rawRetentionDays: 6 },
    { logRetentionDays: 30.5 },
    { logRetentionDays: "30" },
    { rawRetentionDays: null },
    {},
  ]) {
    assert.equal(validateRetentionUpdate(input, current).ok, false, JSON.stringify(input));
  }
});

test("raw data never exceeds three months even with acknowledgement", () => {
  const result = validateRetentionUpdate(
    { rawRetentionDays: 365, acknowledgeStorageWarning: true },
    current
  );
  assert.equal(result.ok, false);
});

test("environment defaults fall back and clamp to the allowed range", () => {
  assert.equal(retentionDaysFromEnv(undefined, RETENTION_LIMITS.logs), 30);
  assert.equal(retentionDaysFromEnv("abc", RETENTION_LIMITS.logs), 30);
  assert.equal(retentionDaysFromEnv("1", RETENTION_LIMITS.logs), 7);
  assert.equal(retentionDaysFromEnv("400", RETENTION_LIMITS.raw), 90);
  assert.equal(retentionDaysFromEnv("45", RETENTION_LIMITS.raw), 45);
});

test("cutoff is the given number of days before now", () => {
  const now = new Date("2026-11-08T03:30:00.000Z");
  assert.equal(retentionCutoff(now, 30).toISOString(), "2026-10-09T03:30:00.000Z");
});

test("raw host policy normalizes domains and keeps the longest shared retention", () => {
  const policy = buildRawHostPolicy(
    [
      { domains: ["Shop.Example.com.", "api.example.com"], rawRetentionDays: 14 },
      { domains: ["api.example.com"], rawRetentionDays: 60 },
      { domains: ["unknown", ""], rawRetentionDays: 90 },
    ],
    normalizeModsecHostname
  );
  assert.deepEqual(
    [...policy.entries()].sort(),
    [
      ["api.example.com", 60],
      ["shop.example.com", 14],
    ]
  );
});
