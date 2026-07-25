import assert from "node:assert/strict";
import { test } from "node:test";
import { buildHostCondition, hostMatchesFilter } from "../../utils/hostFilter";

/**
 * Selecting a host shows logs for that host only. apidev.gnzabe.com and
 * apiprod.gnzabe.com are separate options that never leak into each other.
 */

test("a filter matches only the host itself", () => {
  assert.equal(hostMatchesFilter("apidev.gnzabe.com", "apidev.gnzabe.com"), true);
  assert.equal(hostMatchesFilter("gnzabe.com", "gnzabe.com"), true);
});

test("subdomains are NOT included when filtering the apex", () => {
  // The whole point: picking gnzabe.com must not return every subdomain,
  // which would be indistinguishable from applying no filter at all.
  assert.equal(hostMatchesFilter("apidev.gnzabe.com", "gnzabe.com"), false);
  assert.equal(hostMatchesFilter("apiprod.gnzabe.com", "gnzabe.com"), false);
  assert.equal(hostMatchesFilter("a.b.c.gnzabe.com", "gnzabe.com"), false);
});

test("sibling subdomains never leak into each other", () => {
  assert.equal(hostMatchesFilter("apiprod.gnzabe.com", "apidev.gnzabe.com"), false);
  assert.equal(hostMatchesFilter("apidev.gnzabe.com", "apiprod.gnzabe.com"), false);
  assert.equal(hostMatchesFilter("www.gnzabe.com", "apidev.gnzabe.com"), false);
});

test("the apex is not returned when filtering a subdomain", () => {
  assert.equal(hostMatchesFilter("gnzabe.com", "apidev.gnzabe.com"), false);
});

test("lookalike domains do not match", () => {
  // These all pass a substring test, the behaviour originally shipped.
  assert.equal(hostMatchesFilter("notgnzabe.com", "gnzabe.com"), false);
  assert.equal(hostMatchesFilter("my-gnzabe.com", "gnzabe.com"), false);
  assert.equal(hostMatchesFilter("gnzabe.com.attacker.net", "gnzabe.com"), false);
});

test("a short filter does not match everything", () => {
  assert.equal(hostMatchesFilter("banana.com", "a.co"), false);
  assert.equal(hostMatchesFilter("data.com", "a.co"), false);
  assert.equal(hostMatchesFilter("a.co", "a.co"), true);
});

test("matching ignores case and a trailing dot", () => {
  assert.equal(hostMatchesFilter("APIDEV.GNZABE.COM", "apidev.gnzabe.com"), true);
  assert.equal(hostMatchesFilter("apidev.gnzabe.com", "APIDEV.GNZABE.COM"), true);
  assert.equal(hostMatchesFilter("apidev.gnzabe.com", "apidev.gnzabe.com."), true);
  assert.equal(hostMatchesFilter("apidev.gnzabe.com.", "apidev.gnzabe.com"), true);
});

test("an empty filter matches everything", () => {
  assert.equal(hostMatchesFilter("apidev.gnzabe.com", ""), true);
  assert.equal(hostMatchesFilter("apidev.gnzabe.com", "   "), true);
});

test("the prisma condition is an exact match", () => {
  assert.deepEqual(buildHostCondition("  APIDEV.GNZABE.com.  "), {
    OR: [{ host: { equals: "apidev.gnzabe.com", mode: "insensitive" } }],
  });
});

test("the condition never uses substring or suffix matching", () => {
  const serialized = JSON.stringify(buildHostCondition("gnzabe.com"));

  assert.equal(
    serialized.includes("contains"),
    false,
    "a substring match would reintroduce the lookalike-domain bug"
  );
  assert.equal(
    serialized.includes("endsWith"),
    false,
    "a suffix match would pull in every subdomain of the selected host"
  );
});
