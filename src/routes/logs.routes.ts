import { Router, Request, Response } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import { getLocalLocationsFromIPs } from "../utils/ipGeolocation";
import { buildHostCondition } from "../utils/hostFilter";
import {
  type AnalyticsAggregateRow,
  buildLogAnalyticsResponse,
  getAnalyticsWindow,
  parseAnalyticsRange,
} from "../services/logAnalytics";
import {
  type AttackOrigin,
  aggregateAttackOrigins,
} from "../services/attackOrigins";

const router = Router();

const ATTACK_ORIGINS_CACHE_TTL_MS = 60 * 1000;
const ATTACK_ORIGINS_CACHE_MAX_ENTRIES = 100;
const ATTACK_ORIGINS_WINDOW_DAYS = 30;
const ATTACK_ORIGINS_WINDOW_MS =
  ATTACK_ORIGINS_WINDOW_DAYS * 24 * 60 * 60 * 1000;
const attackOriginsCache = new Map<
  string,
  { expiresAt: number; origins: AttackOrigin[] }
>();
const attackOriginsInFlight = new Map<string, Promise<AttackOrigin[]>>();

function normalizedHost(value?: string): string {
  return (value ?? "").trim().toLowerCase().replace(/\.+$/, "");
}

function attackOriginsCacheKey(
  currentUser: {
    role: string | null;
    memberships: { organizationId: string }[];
  },
  host?: string
): string {
  const accessKey =
    currentUser.role === "super_admin"
      ? "super-admin:all"
      : `organizations:${currentUser.memberships
          .map((membership) => membership.organizationId)
          .sort()
          .join(",")}`;
  return `${accessKey}|host:${normalizedHost(host) || "all"}`;
}

function cacheAttackOrigins(key: string, origins: AttackOrigin[]): void {
  const now = Date.now();
  for (const [cacheKey, entry] of attackOriginsCache) {
    if (entry.expiresAt <= now) attackOriginsCache.delete(cacheKey);
  }

  if (attackOriginsCache.size >= ATTACK_ORIGINS_CACHE_MAX_ENTRIES) {
    const oldestKey = attackOriginsCache.keys().next().value;
    if (oldestKey) attackOriginsCache.delete(oldestKey);
  }

  attackOriginsCache.set(key, {
    origins,
    expiresAt: now + ATTACK_ORIGINS_CACHE_TTL_MS,
  });
}

/**
 * Restrict a query to the logs a user is allowed to see.
 *
 * Returns null when the user has no organizations, meaning the caller should
 * short-circuit to an empty result rather than querying.
 */
function buildAccessScope(
  currentUser: {
    role: string | null;
    memberships: { organizationId: string }[];
  },
  organizationIdFilter?: string
): Record<string, any> | null {
  if (currentUser.role === "super_admin") {
    return organizationIdFilter
      ? { organizationId: organizationIdFilter }
      : {};
  }

  const userOrganizationIds = currentUser.memberships.map(
    (m) => m.organizationId
  );

  if (userOrganizationIds.length === 0) return null;

  return { organizationId: { in: userOrganizationIds } };
}

/**
 * @swagger
 * tags:
 *   name: Logs
 *   description: Log management endpoints
 */

/**
 * @swagger
 * /api/logs:
 *   get:
 *     summary: Get logs (filtered by user role)
 *     tags: [Logs]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *         description: Items per page
 *       - in: query
 *         name: organizationId
 *         schema:
 *           type: string
 *         description: Filter by organization ID (super_admin only)
 *       - in: query
 *         name: host
 *         schema:
 *           type: string
 *         description: Filter by host
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [CRITICAL, HIGH, MEDIUM, LOW]
 *         description: Filter by severity
 *       - in: query
 *         name: action
 *         schema:
 *           type: string
 *           enum: [blocked, warning]
 *         description: Filter by action
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in requestUrl, clientIp, ruleId, or message
 *     responses:
 *       200:
 *         description: List of logs
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 logs:
 *                   type: array
 *                   items:
 *                     type: object
 *                 total:
 *                   type: integer
 *                 page:
 *                   type: integer
 *                 limit:
 *                   type: integer
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Server error
 */
router.get("/", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token with Supabase
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from our database
    const currentUser = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      include: {
        memberships: {
          where: {
            status: "verified",
          },
          select: {
            organizationId: true,
          },
        },
      },
    });

    if (!currentUser) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Parse query parameters
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 10, 100); // Max 100 per page
    const skip = (page - 1) * limit;

    const organizationIdFilter = req.query.organizationId as string | undefined;
    const hostFilter = req.query.host as string | undefined;
    const severityFilter = req.query.severity as string | undefined;
    const actionFilter = req.query.action as string | undefined;
    const searchQuery = req.query.search as string | undefined;

    // Build where clause
    const where: any = {};

    // For super_admin: show all logs (or filter by organizationId if provided)
    // For regular users: only show logs from their organizations
    if (currentUser.role === "super_admin") {
      if (organizationIdFilter) {
        where.organizationId = organizationIdFilter;
      }
      // If no organizationId filter, show all logs
    } else {
      // Regular user: only show logs from their organizations
      const userOrganizationIds = currentUser.memberships.map(
        (m) => m.organizationId
      );

      if (userOrganizationIds.length === 0) {
        // User has no organizations, return empty result
        return res.json({
          logs: [],
          total: 0,
          page,
          limit,
        });
      }

      where.organizationId = {
        in: userOrganizationIds,
      };
    }

    // Apply filters.
    //
    // Each filter that needs an OR goes into its own AND entry. Assigning
    // where.OR directly would mean the host filter and the search filter
    // overwrite one another, silently dropping whichever was set first.
    const conditions: any[] = [];

    if (hostFilter) {
      conditions.push(buildHostCondition(hostFilter));
    }

    if (severityFilter) {
      where.severity = severityFilter;
    }

    if (actionFilter) {
      where.action = actionFilter;
    }

    // Search filter (search in multiple fields)
    if (searchQuery) {
      conditions.push({
        OR: [
          { requestUrl: { contains: searchQuery, mode: "insensitive" } },
          { clientIp: { contains: searchQuery, mode: "insensitive" } },
          { ruleId: { contains: searchQuery, mode: "insensitive" } },
          { message: { contains: searchQuery, mode: "insensitive" } },
          { host: { contains: searchQuery, mode: "insensitive" } },
        ],
      });
    }

    if (conditions.length > 0) {
      where.AND = conditions;
    }

    // Fetch logs with pagination
    const [logs, total] = await Promise.all([
      prisma.log.findMany({
        where,
        skip,
        take: limit,
        orderBy: {
          timestamp: "desc",
        },
        include: {
          organization: {
            select: {
              id: true,
              name: true,
              domains: true,
            },
          },
        },
      }),
      prisma.log.count({ where }),
    ]);

    // Transform logs to match frontend format
    const transformedLogs = logs.map((log) => ({
      id: log.id,
      timestamp: log.timestamp.toISOString(),
      createdAt: log.createdAt.toISOString(),
      clientIp: log.clientIp,
      clientCountry: "Unknown", // Not stored in DB, could be added later
      host: log.host,
      method: log.method as
        | "GET"
        | "POST"
        | "PUT"
        | "DELETE"
        | "PATCH"
        | "OPTIONS",
      requestUri: log.requestUrl,
      ruleName: log.rule || "Unknown Rule",
      ruleId: log.ruleId || "-",
      severity: log.severity.toLowerCase() as
        | "critical"
        | "high"
        | "medium"
        | "low",
      action: log.action as "blocked" | "warning",
      userAgent: log.userAgent || "",
      headers: (log.headers as Record<string, string>) || {},
      requestBody: undefined, // Not stored in DB
      responseCode: log.responseCode || undefined,
      organizationId: log.organizationId,
      organization: log.organization
        ? {
            id: log.organization.id,
            name: log.organization.name,
            domains: log.organization.domains,
          }
        : null,
    }));

    res.json({
      logs: transformedLogs,
      total,
      page,
      limit,
    });
  } catch (error) {
    console.error("Error fetching logs:", error);
    res.status(500).json({
      message: "Failed to fetch logs",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/logs/hosts:
 *   get:
 *     summary: List the hosts that actually appear in the caller's logs
 *     description: >
 *       Returns the distinct host values present in logs the caller can see,
 *       with a count for each. The organization's registered domains are the
 *       apex names (for example gnzabe.com) while traffic arrives on
 *       subdomains (apiprod.gnzabe.com), so a selector built only from
 *       registered domains cannot target the host you actually want.
 *     tags: [Logs]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Distinct hosts with log counts, most frequent first
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hosts:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       host:
 *                         type: string
 *                       count:
 *                         type: integer
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get("/hosts", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    const currentUser = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      select: {
        id: true,
        role: true,
        memberships: {
          where: { status: "verified" },
          select: { organizationId: true },
        },
      },
    });

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    const organizationIdFilter = req.query.organizationId as string | undefined;
    const scope = buildAccessScope(currentUser, organizationIdFilter);

    // No organizations means no logs to describe.
    if (scope === null) {
      return res.json({ hosts: [] });
    }

    const grouped = await prisma.log.groupBy({
      by: ["host"],
      where: scope,
      _count: { host: true },
      orderBy: { _count: { host: "desc" } },
    });

    res.json({
      hosts: grouped
        .filter((row) => row.host && row.host.trim() !== "")
        .map((row) => ({ host: row.host, count: row._count.host })),
    });
  } catch (error) {
    console.error("Error fetching log hosts:", error);
    res.status(500).json({
      message: "Failed to fetch log hosts",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/logs/analytics:
 *   get:
 *     summary: Get range-aware overview metrics and attack trend buckets
 *     tags: [Logs]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: range
 *         schema:
 *           type: string
 *           enum: [24h, 7d, 30d, 3m]
 *           default: 24h
 *       - in: query
 *         name: host
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Aggregated metrics and zero-filled time buckets
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get("/analytics", async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    const currentUser = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      include: {
        memberships: {
          where: { status: "verified" },
          select: { organizationId: true },
        },
      },
    });

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    const range = parseAnalyticsRange(req.query.range);
    const window = getAnalyticsWindow(range);
    const scope = buildAccessScope(currentUser);

    if (scope === null) {
      return res.json(buildLogAnalyticsResponse(range, window, []));
    }

    const startTimestamp = window.start.toISOString().replace(/Z$/, "");
    const endTimestamp = window.end.toISOString().replace(/Z$/, "");
    const bucketSizeSeconds = window.bucketSizeMs / 1000;
    const conditions: Prisma.Sql[] = [
      Prisma.sql`"timestamp" >= ${startTimestamp}::timestamp`,
      Prisma.sql`"timestamp" < ${endTimestamp}::timestamp`,
    ];

    if (currentUser.role !== "super_admin") {
      const organizationIds = currentUser.memberships.map(
        (membership) => membership.organizationId
      );
      conditions.push(
        Prisma.sql`"organizationId" IN (${Prisma.join(organizationIds)})`
      );
    }

    const host = normalizedHost(req.query.host as string | undefined);
    if (host) {
      conditions.push(Prisma.sql`LOWER("host") = ${host}`);
    }

    // Aggregate inside PostgreSQL so a dashboard response is at most 30 rows,
    // regardless of whether the selected period contains 100 or 10M events.
    const rows = await prisma.$queryRaw<AnalyticsAggregateRow[]>(Prisma.sql`
      SELECT
        FLOOR(
          EXTRACT(
            EPOCH FROM ("timestamp" - ${startTimestamp}::timestamp)
          )
          / ${bucketSizeSeconds}
        )::integer AS "bucketIndex",
        COUNT(*) AS "attacks",
        COUNT(*) FILTER (
          WHERE LOWER("action") = 'blocked'
        ) AS "blocked",
        COUNT(*) FILTER (
          WHERE UPPER("severity") = 'CRITICAL'
        ) AS "critical",
        COUNT(*) FILTER (
          WHERE UPPER("severity") = 'HIGH'
        ) AS "high",
        COUNT(*) FILTER (
          WHERE UPPER("severity") = 'MEDIUM'
        ) AS "medium",
        COUNT(*) FILTER (
          WHERE UPPER("severity") = 'LOW'
        ) AS "low"
      FROM "Log"
      WHERE ${Prisma.join(conditions, " AND ")}
      GROUP BY 1
      ORDER BY 1
    `);

    // React Query owns the short client cache. Do not let a browser HTTP cache
    // replay authenticated tenant data after an account switch.
    res.setHeader("Cache-Control", "private, no-store");
    res.json(buildLogAnalyticsResponse(range, window, rows));
  } catch (error) {
    console.error("Error fetching log analytics:", error);
    res.status(500).json({
      message: "Failed to fetch log analytics",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/logs/attack-origins:
 *   get:
 *     summary: Get attack origins grouped by country
 *     tags: [Logs]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: host
 *         schema:
 *           type: string
 *         description: Filter by host
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *         description: Maximum number of origins to return
 *     responses:
 *       200:
 *         description: List of attack origins
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 origins:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       ip:
 *                         type: string
 *                       country:
 *                         type: string
 *                       countryCode:
 *                         type: string
 *                       lat:
 *                         type: number
 *                       lng:
 *                         type: number
 *                       count:
 *                         type: integer
 *                       ipCount:
 *                         type: integer
 *                       severity:
 *                         type: string
 *                         enum: [high, medium, low]
 *                 windowDays:
 *                   type: integer
 *                   example: 30
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get("/attack-origins", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token with Supabase
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from our database
    const currentUser = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      include: {
        memberships: {
          where: {
            status: "verified",
          },
          select: {
            organizationId: true,
          },
        },
      },
    });

    if (!currentUser) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const hostFilter = normalizedHost(req.query.host as string | undefined);
    const requestedLimit = Number.parseInt(req.query.limit as string, 10);
    const limit = Number.isFinite(requestedLimit)
      ? Math.max(1, Math.min(requestedLimit, 100))
      : 50;

    const scope = buildAccessScope(currentUser);
    if (scope === null) {
      return res.json({ origins: [], windowDays: ATTACK_ORIGINS_WINDOW_DAYS });
    }

    const where: any = { ...scope };

    // Apply the same exact, case-insensitive host rule as the log table.
    if (hostFilter) {
      where.AND = [buildHostCondition(hostFilter)];
    }

    // A geographic dashboard is useful for current attack activity, not an
    // ever-growing all-time archive. Bounding the window also keeps cold-cache
    // aggregation fast as the log table grows.
    const windowEnd = new Date();
    where.timestamp = {
      gte: new Date(windowEnd.getTime() - ATTACK_ORIGINS_WINDOW_MS),
      lt: windowEnd,
    };

    const cacheKey = attackOriginsCacheKey(currentUser, hostFilter);
    const cached = attackOriginsCache.get(cacheKey);
    let origins: AttackOrigin[];

    if (cached && cached.expiresAt > Date.now()) {
      origins = cached.origins;
    } else {
      let pending = attackOriginsInFlight.get(cacheKey);

      if (!pending) {
        pending = (async () => {
          // The database returns one compact row per IP/severity combination.
          // This replaces loading, sorting, and walking every historical log.
          const groupedLogs = await prisma.log.groupBy({
            by: ["clientIp", "severity"],
            where,
            _count: { _all: true },
          });
          const locations = getLocalLocationsFromIPs(
            groupedLogs.map((row) => row.clientIp)
          );
          return aggregateAttackOrigins(groupedLogs, locations);
        })();

        attackOriginsInFlight.set(cacheKey, pending);
        const clearPending = () => {
          if (attackOriginsInFlight.get(cacheKey) === pending) {
            attackOriginsInFlight.delete(cacheKey);
          }
        };
        pending.then(clearPending, clearPending);
      }

      origins = await pending;
      cacheAttackOrigins(cacheKey, origins);
    }

    // The scoped server cache above provides the speed-up; authenticated
    // responses themselves must not be reusable by a browser after logout.
    res.setHeader("Cache-Control", "private, no-store");
    res.json({
      origins: origins.slice(0, limit),
      windowDays: ATTACK_ORIGINS_WINDOW_DAYS,
    });
  } catch (error) {
    console.error("Error fetching attack origins:", error);
    res.status(500).json({
      message: "Failed to fetch attack origins",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/logs/{id}:
 *   get:
 *     summary: Get log by ID
 *     tags: [Logs]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Log ID
 *     responses:
 *       200:
 *         description: Log details
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Log not found
 *       500:
 *         description: Server error
 */
router.get("/:id", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token with Supabase
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from our database
    const currentUser = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      include: {
        memberships: {
          where: {
            status: "verified",
          },
          select: {
            organizationId: true,
          },
        },
      },
    });

    if (!currentUser) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id } = req.params;

    // Fetch log
    const log = await prisma.log.findUnique({
      where: { id },
      include: {
        organization: {
          select: {
            id: true,
            name: true,
            domains: true,
          },
        },
      },
    });

    if (!log) {
      return res.status(404).json({
        message: "Log not found",
      });
    }

    // Check access: super_admin can access all, regular users only their orgs
    if (currentUser.role !== "super_admin") {
      const userOrganizationIds = currentUser.memberships.map(
        (m) => m.organizationId
      );

      if (
        !log.organizationId ||
        !userOrganizationIds.includes(log.organizationId)
      ) {
        return res.status(403).json({
          message: "Forbidden: You don't have access to this log",
        });
      }
    }

    // Transform log to match frontend format
    const transformedLog = {
      id: log.id,
      timestamp: log.timestamp.toISOString(),
      createdAt: log.createdAt.toISOString(),
      clientIp: log.clientIp,
      clientCountry: "Unknown",
      host: log.host,
      method: log.method as
        | "GET"
        | "POST"
        | "PUT"
        | "DELETE"
        | "PATCH"
        | "OPTIONS",
      requestUri: log.requestUrl,
      ruleName: log.rule || "Unknown Rule",
      ruleId: log.ruleId || "-",
      severity: log.severity.toLowerCase() as
        | "critical"
        | "high"
        | "medium"
        | "low",
      action: log.action as "blocked" | "warning",
      userAgent: log.userAgent || "",
      headers: (log.headers as Record<string, string>) || {},
      requestBody: undefined,
      responseCode: log.responseCode || undefined,
      organizationId: log.organizationId,
      organization: log.organization
        ? {
            id: log.organization.id,
            name: log.organization.name,
            domains: log.organization.domains,
          }
        : null,
      message: log.message,
      maturity: log.maturity,
      responseHeader: log.responseHeader as Record<string, string> | undefined,
    };

    res.json(transformedLog);
  } catch (error) {
    console.error("Error fetching log:", error);
    res.status(500).json({
      message: "Failed to fetch log",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

export { router as logsRoutes };
