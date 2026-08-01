import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import type { Prisma } from "@prisma/client";
import {
  extractModsecHost,
  normalizeLandingBatchSize,
  parseModsecLandingData,
  resolveOrganizationByHost,
} from "../modsecProcessor";

const processorPath = resolve(__dirname, "../modsecProcessor.ts");

const transaction = {
  client_ip: "203.0.113.8",
  time_stamp: "2026-08-01T10:00:00.000Z",
  request: {
    method: "GET",
    hostname: "api.example.com",
    uri: "/health",
    headers: { Host: "api.example.com:443" },
  },
  messages: [],
};

function json(value: unknown): Prisma.JsonValue {
  return value as Prisma.JsonValue;
}

test("landing parser accepts every supported Fluent Bit wrapper", () => {
  const encoded = JSON.stringify({ transaction });
  const cases: Prisma.JsonValue[] = [
    json({ transaction }),
    json({ raw: encoded }),
    json({ data: encoded }),
    json({ data: { transaction } }),
    json({ data: transaction }),
    json(transaction),
    json(encoded),
    json(JSON.stringify(encoded)),
  ];

  for (const value of cases) {
    assert.deepEqual(parseModsecLandingData(value).transaction, transaction);
  }
});

test("a malformed high-precedence wrapper fails instead of changing identity", () => {
  assert.throws(
    () =>
      parseModsecLandingData(
        json({ raw: "{not-json", data: { transaction } })
      ),
    /Unexpected token|Expected property name/
  );
});

test("malformed or incomplete landing payloads fail with bounded errors", () => {
  assert.throws(
    () => parseModsecLandingData(json(null)),
    /JSON object or encoded JSON string/
  );
  assert.throws(
    () => parseModsecLandingData(json({ transaction: { client_ip: "x" } })),
    /missing request/
  );
  assert.throws(
    () =>
      parseModsecLandingData(
        json({ data: { data: { data: { data: { data: { data: transaction } } } } } })
      ),
    /nested too deeply/
  );
});

test("host extraction shares canonical source-host behavior and header fallback", () => {
  const fromHostname = parseModsecLandingData(
    json({
      transaction: {
        ...transaction,
        request: {
          ...transaction.request,
          hostname: " API.EXAMPLE.COM.:443 ",
        },
      },
    })
  );
  assert.equal(extractModsecHost(fromHostname), "api.example.com");

  const fromHeader = parseModsecLandingData(
    json({
      transaction: {
        ...transaction,
        request: {
          ...transaction.request,
          hostname: "unknown",
          headers: { hOsT: "[2001:DB8::1]:443" },
        },
      },
    })
  );
  assert.equal(extractModsecHost(fromHeader), "2001:db8::1");
});

test("organization attribution remains exact and rejects ambiguous domains", () => {
  const organizations = [
    { id: "apex", domains: ["example.com"] },
    { id: "api", domains: [" API.EXAMPLE.COM. "] },
  ];

  assert.equal(resolveOrganizationByHost("example.com", organizations), "apex");
  assert.equal(resolveOrganizationByHost("api.example.com:443", organizations), "api");
  assert.equal(resolveOrganizationByHost("sub.api.example.com", organizations), null);
  assert.equal(
    resolveOrganizationByHost("unknown", [{ id: "bad", domains: ["unknown"] }]),
    null
  );

  assert.equal(
    resolveOrganizationByHost("example.com", [
      { id: "one", domains: ["example.com"] },
      { id: "two", domains: ["EXAMPLE.COM"] },
    ]),
    null
  );
});

test("batch size normalization prevents empty loops and oversized transactions", () => {
  assert.equal(normalizeLandingBatchSize(Number.NaN), 100);
  assert.equal(normalizeLandingBatchSize(0), 1);
  assert.equal(normalizeLandingBatchSize(-50), 1);
  assert.equal(normalizeLandingBatchSize(25.9), 25);
  assert.equal(normalizeLandingBatchSize(50_000), 1_000);
});

test("batch implementation uses keyset claims and one atomic bulk write", () => {
  const source = readFileSync(processorPath, "utf8");
  const batchStart = source.indexOf("async function processClaimedBatch");
  const drainStart = source.indexOf(
    "export async function processAllModsecLandingRecords"
  );
  assert.notEqual(batchStart, -1);
  assert.notEqual(drainStart, -1);

  const batchSource = source.slice(batchStart, drainStart);
  const drainSource = source.slice(drainStart);
  assert.match(batchSource, /FOR UPDATE SKIP LOCKED/);
  assert.match(batchSource, /"id" > \$\{afterId\}/);
  assert.match(batchSource, /"id" <= \$\{throughId\}/);
  assert.match(batchSource, /createManyAndReturn/);
  assert.match(batchSource, /modsecLanding\.updateMany/);
  assert.match(batchSource, /fallbackClaimedRecords/);
  assert.doesNotMatch(drainSource, /\bskip\b\s*[:,=]/);
  assert.match(drainSource, /_max:\s*\{ id: true \}/);
  assert.match(drainSource, /batch-after-\$\{cursor\.toString\(\)\}/);
  assert.match(drainSource, /cursor = batch\.cursor/);
});

test("single-row and bulk paths enforce the explicit processed=false queue", () => {
  const source = readFileSync(processorPath, "utf8");
  assert.match(source, /processed is null/);
  assert.match(source, /WHERE "processed" = false/);
  assert.doesNotMatch(source, /"processed" IS NOT TRUE/);
});
