import assert from "node:assert/strict";
import { test } from "node:test";
import { buildHostCondition, hostMatchesFilter } from "../../utils/hostFilter";

/**
 * The host selector previously used a substring match, which is why filtering
 * looked like it did nothing: picking "gnzabe.com" matched every host with
 * that text anywhere in it, and short domains matched almost everything.
 */

test("a filter matches the host itself", () => {
  assert.equal(hostMatchesFilter("gnzabe.com", "gnzabe.com"), true);
  assert.equal(hostMatchesFilter("apiprod.gnzabe.com", "apiprod.gnzabe.com"), true);
});

test("a filter matches subdomains of the host", () => {
  assert.equal(hostMatchesFilter("apiprod.gnzabe.com", "gnzabe.com"), true);
  assert.equal(hostMatchesFilter("a.b.c.gnzabe.com", "gnzabe.com"), true);
  assert.equal(hostMatchesFilter("deep.apiprod.gnzabe.com", "apiprod.gnzabe.com"), true);
});

test("a filter does NOT match a sibling subdomain", () => {
  // Selecting the specific host must exclude the rest of the domain.
  assert.equal(hostMatchesFilter("www.gnzabe.com", "apiprod.gnzabe.com"), false);
  assert.equal(hostMatchesFilter("gnzabe.com", "apiprod.gnzabe.com"), false);
});

test("a filter does NOT match a lookalike domain", () => {
  // These all pass a substring test, which is the bug being fixed.
  assert.equal(hostMatchesFilter("notgnzabe.com", "gnzabe.com"), false);
  assert.equal(hostMatchesFilter("my-gnzabe.com", "gnzabe.com"), false);
  assert.equal(hostMatchesFilter("gnzabe.com.attacker.net", "gnzabe.com"), false);
  assert.equal(hostMatchesFilter("xgnzabe.com", "gnzabe.com"), false);
});

test("a short filter does not match everything", () => {
  // "a.co" as a substring appears inside all of these.
  assert.equal(hostMatchesFilter("banana.com", "a.co"), false);
  assert.equal(hostMatchesFilter("data.com", "a.co"), false);
  assert.equal(hostMatchesFilter("a.co", "a.co"), true);
  assert.equal(hostMatchesFilter("api.a.co", "a.co"), true);
});

test("matching ignores case and a trailing dot", () => {
  assert.equal(hostMatchesFilter("APIPROD.GNZABE.COM", "gnzabe.com"), true);
  assert.equal(hostMatchesFilter("apiprod.gnzabe.com", "GNZABE.COM"), true);
  assert.equal(hostMatchesFilter("apiprod.gnzabe.com", "gnzabe.com."), true);
  assert.equal(hostMatchesFilter("apiprod.gnzabe.com.", "gnzabe.com"), true);
});

test("the prisma condition is an exact-or-subdomain OR", () => {
  const condition = buildHostCondition("  GNZABE.com.  ");

  assert.deepEqual(condition, {
    OR: [
      { host: { equals: "gnzabe.com", mode: "insensitive" } },
      { host: { endsWith: ".gnzabe.com", mode: "insensitive" } },
    ],
  });
});

test("the condition never uses a bare substring match", () => {
  const serialized = JSON.stringify(buildHostCondition("gnzabe.com"));
  assert.equal(
    serialized.includes("contains"),
    false,
    "a substring match would reintroduce the lookalike-domain bug"
  );
});
