import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import { normalizeModsecHostname } from "../../utils/modsecHostname";

const migrationPath = resolve(
  __dirname,
  "../../../prisma/migrations/20260801090000_add_modsec_landing_source_host/migration.sql"
);
const schemaPath = resolve(__dirname, "../../../prisma/schema.prisma");
const logsRoutePath = resolve(__dirname, "../../routes/logs.routes.ts");

test("API host normalization matches the database source-host contract", () => {
  assert.equal(normalizeModsecHostname(" Example.COM.:443 "), "example.com");
  assert.equal(normalizeModsecHostname("SUB.example.com"), "sub.example.com");
  assert.equal(normalizeModsecHostname("[2001:DB8::1]:443"), "2001:db8::1");
  assert.equal(normalizeModsecHostname("2001:DB8::1"), "2001:db8::1");
  assert.equal(normalizeModsecHostname("example.com:65536"), null);
  assert.equal(normalizeModsecHostname("example.com:not-a-port"), null);
  assert.equal(normalizeModsecHostname("https://example.com"), null);
  assert.equal(normalizeModsecHostname("bad host"), null);
});

test("schema exposes the nullable mapped sourceHost field", () => {
  const schema = readFileSync(schemaPath, "utf8");

  assert.match(schema, /sourceHost\s+String\?\s+@map\("source_host"\)/);
});

test("migration safely maintains and indexes pending source hosts", () => {
  const migration = readFileSync(migrationPath, "utf8");

  assert.match(migration, /ADD COLUMN "source_host" TEXT/);
  const rawWrapper = migration.indexOf(
    "IF jsonb_typeof(payload->'raw') = 'string'"
  );
  const dataWrapper = migration.indexOf(
    "ELSIF jsonb_typeof(payload->'data') = 'string'"
  );
  const directTransaction = migration.indexOf(
    "ELSIF jsonb_typeof(payload->'transaction') = 'object'"
  );
  assert.ok(rawWrapper >= 0);
  assert.ok(dataWrapper > rawWrapper);
  assert.ok(directTransaction > dataWrapper);
  assert.match(migration, /normalized <> 'unknown'/);
  assert.match(
    migration,
    /NULLIF\(public\.normalize_modsec_source_host\(raw_host\), 'unknown'\)/
  );
  assert.match(
    migration,
    /BEFORE INSERT OR UPDATE OF "data"\s+ON "modsec_landing"/
  );
  assert.match(migration, /EXCEPTION WHEN OTHERS THEN\s+RETURN NULL/);
  assert.match(
    migration,
    /UPDATE "modsec_landing"\s+SET "source_host"[\s\S]+WHERE "processed" = false/
  );
  assert.match(
    migration,
    /CREATE INDEX "modsec_landing_pending_source_host_time_idx"[\s\S]+\("source_host", "time"\)[\s\S]+WHERE "processed" = false/
  );
  assert.match(
    migration,
    /CREATE INDEX "modsec_landing_pending_id_idx"[\s\S]+\("id"\)[\s\S]+WHERE "processed" = false/
  );
});

test("processing status uses an indexed aggregate instead of loading JSON rows", () => {
  const routes = readFileSync(logsRoutePath, "utf8");
  const start = routes.indexOf('router.get("/processing-status"');
  const end = routes.indexOf('router.get("/:id"', start);

  assert.notEqual(start, -1);
  assert.notEqual(end, -1);

  const processingStatusRoute = routes.slice(start, end);
  assert.match(processingStatusRoute, /processed:\s*false/);
  assert.match(processingStatusRoute, /where\.sourceHost/);
  assert.match(processingStatusRoute, /prisma\.modsecLanding\.aggregate/);
  assert.doesNotMatch(processingStatusRoute, /modsecLanding\.findMany/);
});
