import { Router, Request, Response } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import {
  RETENTION_LIMITS,
  validateRetentionUpdate,
} from "../services/dataRetentionPolicy";
import { getDataRetentionSchedule } from "../services/dataRetentionCron";

const router = Router();

const DAY_MS = 24 * 60 * 60 * 1000;

/** Used when the table is too small to measure a meaningful average. */
const FALLBACK_LOG_ROW_BYTES = 2_000;
const FALLBACK_RAW_ROW_BYTES = 5_000;
const MIN_ROWS_FOR_MEASUREMENT = 1_000;

/**
 * @swagger
 * tags:
 *   name: Data Retention
 *   description: How long organized logs and raw ModSecurity data are kept
 */

type AccessResult =
  | { ok: true; canManage: boolean }
  | { ok: false; status: number; message: string };

/**
 * Any verified member may view retention. Only organization admins and
 * super admins may change it.
 */
async function checkAccess(
  token: string | undefined,
  organizationId: string,
  requireManage: boolean
): Promise<AccessResult> {
  if (!token) {
    return { ok: false, status: 401, message: "No token provided" };
  }

  const {
    data: { user: supabaseUser },
    error,
  } = await supabase.auth.getUser(token);

  if (error || !supabaseUser?.email) {
    return { ok: false, status: 401, message: "Invalid or expired token" };
  }

  const dbUser = await prisma.user.findUnique({
    where: { email: supabaseUser.email },
    select: { id: true, role: true },
  });

  if (!dbUser) {
    return { ok: false, status: 404, message: "User not found" };
  }

  if (dbUser.role === "super_admin") {
    return { ok: true, canManage: true };
  }

  const membership = await prisma.organizationMember.findFirst({
    where: { organizationId, userId: dbUser.id, status: "verified" },
    select: { role: true },
  });

  if (!membership) {
    return { ok: false, status: 403, message: "You do not have access to this organization" };
  }

  const canManage = membership.role === "admin";
  if (requireManage && !canManage) {
    return {
      ok: false,
      status: 403,
      message: "Only organization admins can change data retention",
    };
  }

  return { ok: true, canManage };
}

interface TableSizeRow {
  table: string;
  bytes: number;
  rows: number;
}

/**
 * Average on-disk bytes per row, including indexes and TOAST, from the
 * planner statistics. Cheap: reads pg_class instead of counting rows.
 */
async function averageRowBytes(): Promise<{
  log: number;
  raw: number;
  measured: boolean;
}> {
  try {
    const rows = await prisma.$queryRaw<TableSizeRow[]>(Prisma.sql`
      SELECT c.relname AS "table",
             pg_total_relation_size(c.oid)::float8 AS "bytes",
             GREATEST(c.reltuples, 0)::float8 AS "rows"
      FROM pg_class c
      WHERE c.oid IN (
        to_regclass('public."Log"'),
        to_regclass('public."modsec_landing"')
      )
    `);

    const average = (table: string): number | null => {
      const row = rows.find((item) => item.table === table);
      if (!row || row.rows < MIN_ROWS_FOR_MEASUREMENT) return null;
      const bytes = row.bytes / row.rows;
      if (!Number.isFinite(bytes)) return null;
      return Math.round(Math.min(50_000, Math.max(200, bytes)));
    };

    const log = average("Log");
    const raw = average("modsec_landing");
    return {
      log: log ?? FALLBACK_LOG_ROW_BYTES,
      raw: raw ?? FALLBACK_RAW_ROW_BYTES,
      measured: log !== null && raw !== null,
    };
  } catch (error) {
    console.warn("Data retention: could not read table sizes:", error);
    return { log: FALLBACK_LOG_ROW_BYTES, raw: FALLBACK_RAW_ROW_BYTES, measured: false };
  }
}

/**
 * @swagger
 * /api/organizations/{organizationId}/data-retention:
 *   get:
 *     summary: Get data retention settings, limits and storage usage
 *     tags: [Data Retention]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: organizationId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Current retention, allowed range and recent volume used for storage estimates
 *       401:
 *         description: Missing or invalid token
 *       403:
 *         description: Not a member of the organization
 *       404:
 *         description: Organization not found
 */
router.get("/:organizationId/data-retention", async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");
    const { organizationId } = req.params;

    const access = await checkAccess(token, organizationId, false);
    if (!access.ok) {
      return res.status(access.status).json({ message: access.message });
    }

    const organization = await prisma.organization.findUnique({
      where: { id: organizationId },
      select: {
        id: true,
        logRetentionDays: true,
        rawRetentionDays: true,
        retentionLastRunAt: true,
        retentionLastLogsDeleted: true,
        retentionLastRawDeleted: true,
      },
    });

    if (!organization) {
      return res.status(404).json({ message: "Organization not found" });
    }

    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * DAY_MS);

    const [logCount, logsLast7Days, oldestLog, rowBytes] = await Promise.all([
      prisma.log.count({ where: { organizationId } }),
      prisma.log.count({ where: { organizationId, timestamp: { gte: weekAgo } } }),
      prisma.log.findFirst({
        where: { organizationId },
        orderBy: { timestamp: "asc" },
        select: { timestamp: true },
      }),
      averageRowBytes(),
    ]);

    // A young organization has fewer than 7 days of history, so divide by the
    // days actually observed to avoid underestimating its daily volume.
    let dailyEvents = 0;
    if (oldestLog && logsLast7Days > 0) {
      const observedDays = Math.min(
        7,
        Math.max(1, (now.getTime() - oldestLog.timestamp.getTime()) / DAY_MS)
      );
      dailyEvents = Math.round(logsLast7Days / observedDays);
    }

    return res.json({
      organizationId: organization.id,
      settings: {
        logRetentionDays: organization.logRetentionDays,
        rawRetentionDays: organization.rawRetentionDays,
      },
      limits: RETENTION_LIMITS,
      stats: {
        logCount,
        logsLast7Days,
        dailyEvents,
        oldestLogAt: oldestLog?.timestamp.toISOString() ?? null,
        avgLogRowBytes: rowBytes.log,
        avgRawRowBytes: rowBytes.raw,
        rowSizeMeasured: rowBytes.measured,
      },
      lastRun: organization.retentionLastRunAt
        ? {
            at: organization.retentionLastRunAt.toISOString(),
            logsDeleted: organization.retentionLastLogsDeleted,
            rawDeleted: organization.retentionLastRawDeleted,
          }
        : null,
      schedule: getDataRetentionSchedule(),
      canManage: access.canManage,
    });
  } catch (error) {
    console.error("GET data-retention:", error);
    return res.status(500).json({ message: "Failed to load data retention settings" });
  }
});

/**
 * @swagger
 * /api/organizations/{organizationId}/data-retention:
 *   patch:
 *     summary: Update how long logs and raw data are kept
 *     description: >
 *       Organized logs can be kept 7-365 days and raw ModSecurity JSON 7-90 days.
 *       Raising log retention above 90 days requires acknowledgeStorageWarning=true.
 *     tags: [Data Retention]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: organizationId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               logRetentionDays:
 *                 type: integer
 *                 minimum: 7
 *                 maximum: 365
 *                 example: 30
 *               rawRetentionDays:
 *                 type: integer
 *                 minimum: 7
 *                 maximum: 90
 *                 example: 30
 *               acknowledgeStorageWarning:
 *                 type: boolean
 *                 description: Required when raising logRetentionDays above 90
 *     responses:
 *       200:
 *         description: Updated retention settings
 *       400:
 *         description: Invalid value, or the storage warning was not acknowledged
 *       403:
 *         description: Only organization admins can change retention
 */
router.patch("/:organizationId/data-retention", async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");
    const { organizationId } = req.params;

    const access = await checkAccess(token, organizationId, true);
    if (!access.ok) {
      return res.status(access.status).json({ message: access.message });
    }

    const current = await prisma.organization.findUnique({
      where: { id: organizationId },
      select: { logRetentionDays: true, rawRetentionDays: true },
    });

    if (!current) {
      return res.status(404).json({ message: "Organization not found" });
    }

    const result = validateRetentionUpdate(req.body ?? {}, current);
    if (!result.ok) {
      return res.status(400).json({ message: result.message, code: result.code });
    }

    const updated = await prisma.organization.update({
      where: { id: organizationId },
      data: result.value,
      select: { logRetentionDays: true, rawRetentionDays: true },
    });

    return res.json({ settings: updated });
  } catch (error) {
    console.error("PATCH data-retention:", error);
    return res.status(500).json({ message: "Failed to update data retention settings" });
  }
});

export { router as dataRetentionRoutes };
