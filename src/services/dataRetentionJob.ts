import { Prisma } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { normalizeModsecHostname } from "../utils/modsecHostname";
import {
  buildRawHostPolicy,
  defaultLogRetentionDays,
  defaultRawRetentionDays,
  retentionCutoff,
} from "./dataRetentionPolicy";

/**
 * Deletes data that is older than each organization's retention settings.
 *
 * - Organized logs ("Log") are deleted per organization by event timestamp.
 *   Logs with no organization use DEFAULT_LOG_RETENTION_DAYS.
 * - Raw landing rows ("modsec_landing") are matched to an organization by the
 *   trigger-maintained source_host column. Rows whose host belongs to no
 *   organization, including unparseable rows that were never organized, use
 *   DEFAULT_RAW_RETENTION_DAYS.
 *
 * Everything is deleted in small batches so no single statement holds locks
 * or generates WAL for long, and the ingestion processor keeps running.
 */

export interface OrganizationRetentionResult {
  organizationId: string;
  name: string;
  logRetentionDays: number;
  rawRetentionDays: number;
  logsDeleted: number;
  rawDeleted: number;
}

export interface DataRetentionRunResult {
  dryRun: boolean;
  startedAt: Date;
  finishedAt: Date;
  logsDeleted: number;
  rawDeleted: number;
  organizations: OrganizationRetentionResult[];
  unassigned: {
    logRetentionDays: number;
    rawRetentionDays: number;
    logsDeleted: number;
    rawDeleted: number;
  };
  errors: string[];
}

export interface DataRetentionOptions {
  /** Count what would be deleted without deleting anything. */
  dryRun?: boolean;
  /** Rows deleted per statement. Defaults to DATA_RETENTION_BATCH_SIZE or 5000. */
  batchSize?: number;
}

function resolveBatchSize(value: number | undefined): number {
  const raw = value ?? Number.parseInt(process.env.DATA_RETENTION_BATCH_SIZE || "5000", 10);
  if (!Number.isFinite(raw)) return 5000;
  return Math.min(50_000, Math.max(100, Math.floor(raw)));
}

/** Compare against timestamp-without-time-zone columns, which hold UTC. */
function utcTimestamp(date: Date): Prisma.Sql {
  return Prisma.sql`(${date.toISOString()}::timestamptz AT TIME ZONE 'UTC')`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function purgeLogs(
  organizationId: string | null,
  cutoff: Date,
  batchSize: number,
  dryRun: boolean
): Promise<number> {
  const orgCondition =
    organizationId === null
      ? Prisma.sql`"organizationId" IS NULL`
      : Prisma.sql`"organizationId" = ${organizationId}`;

  if (dryRun) {
    const rows = await prisma.$queryRaw<Array<{ count: number }>>(Prisma.sql`
      SELECT count(*)::int AS "count"
      FROM "Log"
      WHERE ${orgCondition} AND "timestamp" < ${utcTimestamp(cutoff)}
    `);
    return rows[0]?.count ?? 0;
  }

  let total = 0;
  while (true) {
    const deleted = await prisma.$executeRaw(Prisma.sql`
      WITH doomed AS (
        SELECT "id"
        FROM "Log"
        WHERE ${orgCondition} AND "timestamp" < ${utcTimestamp(cutoff)}
        LIMIT ${batchSize}
      )
      DELETE FROM "Log" AS l
      USING doomed
      WHERE l."id" = doomed."id"
    `);
    total += deleted;
    if (deleted < batchSize) return total;
  }
}

interface RawGroupRow {
  host: string | null;
  count: number;
  maxTime: string | null;
}

/**
 * Delete raw landing rows past their host's retention.
 *
 * Walks the time index once from oldest to newest using a keyset cursor, so
 * rows that are kept because their organization chose a longer retention are
 * scanned once per run rather than once per batch.
 *
 * Returns deleted counts keyed by the policy host, or null for rows that fell
 * back to the default retention.
 */
async function purgeRawLanding(
  hostPolicy: Map<string, number>,
  defaultDays: number,
  now: Date,
  batchSize: number,
  dryRun: boolean
): Promise<Map<string | null, number>> {
  const counts = new Map<string | null, number>();
  const hosts = [...hostPolicy.keys()];
  const days = hosts.map((host) => hostPolicy.get(host)!);
  const shortestDays = Math.min(defaultDays, ...days);
  const nowSql = utcTimestamp(now);
  const loosestCutoff = utcTimestamp(retentionCutoff(now, shortestDays));

  // Without any organization hosts every row uses the default retention.
  const policyCte =
    hosts.length > 0
      ? Prisma.sql`policy AS (
          SELECT * FROM unnest(${hosts}::text[], ${days}::int[]) AS p("host", "days")
        )`
      : Prisma.sql`policy AS (
          SELECT NULL::text AS "host", NULL::int AS "days" WHERE false
        )`;

  const expired = Prisma.sql`
    l."time" < ${nowSql} - make_interval(days => COALESCE(p."days", ${defaultDays}::int))
  `;

  const add = (rows: RawGroupRow[]) => {
    for (const row of rows) {
      counts.set(row.host, (counts.get(row.host) ?? 0) + row.count);
    }
  };

  if (dryRun) {
    const rows = await prisma.$queryRaw<RawGroupRow[]>(Prisma.sql`
      WITH ${policyCte}
      SELECT p."host" AS "host", count(*)::int AS "count", NULL::text AS "maxTime"
      FROM "modsec_landing" l
      LEFT JOIN policy p ON p."host" = l."source_host"
      WHERE l."time" < ${loosestCutoff} AND ${expired}
      GROUP BY p."host"
    `);
    add(rows);
    return counts;
  }

  // '-infinity' starts the walk before the oldest row. The cursor is passed
  // back as text so microsecond precision survives the round trip.
  let cursor = "-infinity";
  while (true) {
    const rows = await prisma.$queryRaw<RawGroupRow[]>(Prisma.sql`
      WITH ${policyCte},
      doomed AS (
        SELECT l."id", p."host" AS "policyHost"
        FROM "modsec_landing" l
        LEFT JOIN policy p ON p."host" = l."source_host"
        WHERE l."time" >= ${cursor}::timestamp
          AND l."time" < ${loosestCutoff}
          AND ${expired}
        ORDER BY l."time"
        LIMIT ${batchSize}
      ),
      deleted AS (
        DELETE FROM "modsec_landing" AS d
        USING doomed
        WHERE d."id" = doomed."id"
        RETURNING doomed."policyHost", d."time"
      )
      SELECT "policyHost" AS "host", count(*)::int AS "count", max("time")::text AS "maxTime"
      FROM deleted
      GROUP BY "policyHost"
    `);

    add(rows);
    const deleted = rows.reduce((sum, row) => sum + row.count, 0);
    if (deleted < batchSize) return counts;

    const maxTimes = rows
      .map((row) => row.maxTime)
      .filter((value): value is string => value !== null)
      .sort();
    const next = maxTimes[maxTimes.length - 1];
    if (!next) return counts;
    cursor = next;
  }
}

let running = false;

export function isDataRetentionRunning(): boolean {
  return running;
}

export async function runDataRetention(
  now: Date = new Date(),
  options: DataRetentionOptions = {}
): Promise<DataRetentionRunResult> {
  if (running) {
    throw new Error("A data retention run is already in progress");
  }
  running = true;

  const dryRun = options.dryRun === true;
  const batchSize = resolveBatchSize(options.batchSize);
  const startedAt = new Date();
  const errors: string[] = [];
  const defaultLogDays = defaultLogRetentionDays();
  const defaultRawDays = defaultRawRetentionDays();

  try {
    const organizations = await prisma.organization.findMany({
      select: {
        id: true,
        name: true,
        domains: true,
        logRetentionDays: true,
        rawRetentionDays: true,
      },
    });

    const results = new Map<string, OrganizationRetentionResult>();
    for (const organization of organizations) {
      results.set(organization.id, {
        organizationId: organization.id,
        name: organization.name,
        logRetentionDays: organization.logRetentionDays,
        rawRetentionDays: organization.rawRetentionDays,
        logsDeleted: 0,
        rawDeleted: 0,
      });
    }

    // 1. Organized logs, one organization at a time.
    for (const organization of organizations) {
      try {
        const cutoff = retentionCutoff(now, organization.logRetentionDays);
        results.get(organization.id)!.logsDeleted = await purgeLogs(
          organization.id,
          cutoff,
          batchSize,
          dryRun
        );
      } catch (error) {
        errors.push(`Logs for organization ${organization.id}: ${errorMessage(error)}`);
      }
    }

    let unassignedLogs = 0;
    try {
      unassignedLogs = await purgeLogs(
        null,
        retentionCutoff(now, defaultLogDays),
        batchSize,
        dryRun
      );
    } catch (error) {
      errors.push(`Logs without an organization: ${errorMessage(error)}`);
    }

    // 2. Raw, unorganized landing rows in one pass over the time index.
    const hostPolicy = buildRawHostPolicy(organizations, normalizeModsecHostname);
    const hostOwners = new Map<string, string[]>();
    for (const organization of organizations) {
      for (const domain of organization.domains) {
        const host = normalizeModsecHostname(domain);
        if (!host || !hostPolicy.has(host)) continue;
        const owners = hostOwners.get(host) ?? [];
        if (!owners.includes(organization.id)) owners.push(organization.id);
        hostOwners.set(host, owners);
      }
    }

    let unassignedRaw = 0;
    let rawDeleted = 0;
    try {
      const rawCounts = await purgeRawLanding(
        hostPolicy,
        defaultRawDays,
        now,
        batchSize,
        dryRun
      );
      for (const [host, count] of rawCounts) {
        rawDeleted += count;
        const owners = host === null ? [] : hostOwners.get(host) ?? [];
        if (owners.length === 0) {
          unassignedRaw += count;
          continue;
        }
        // A host shared by several organizations is credited to each of them.
        for (const ownerId of owners) {
          results.get(ownerId)!.rawDeleted += count;
        }
      }
    } catch (error) {
      errors.push(`Raw landing data: ${errorMessage(error)}`);
    }

    // 3. Record the outcome. Raw SQL keeps @updatedAt untouched so routine
    // cleanups do not look like settings changes.
    if (!dryRun) {
      for (const result of results.values()) {
        try {
          await prisma.$executeRaw(Prisma.sql`
            UPDATE "Organization"
            SET "retentionLastRunAt" = ${utcTimestamp(now)},
                "retentionLastLogsDeleted" = ${result.logsDeleted}::int,
                "retentionLastRawDeleted" = ${result.rawDeleted}::int
            WHERE "id" = ${result.organizationId}
          `);
        } catch (error) {
          errors.push(
            `Recording cleanup for organization ${result.organizationId}: ${errorMessage(error)}`
          );
        }
      }
    }

    const organizationResults = [...results.values()];
    return {
      dryRun,
      startedAt,
      finishedAt: new Date(),
      logsDeleted:
        organizationResults.reduce((sum, item) => sum + item.logsDeleted, 0) + unassignedLogs,
      rawDeleted,
      organizations: organizationResults,
      unassigned: {
        logRetentionDays: defaultLogDays,
        rawRetentionDays: defaultRawDays,
        logsDeleted: unassignedLogs,
        rawDeleted: unassignedRaw,
      },
      errors,
    };
  } finally {
    running = false;
  }
}
