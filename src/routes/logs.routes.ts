import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import { getLocationsFromIPs } from "../utils/ipGeolocation";
import { buildHostCondition } from "../utils/hostFilter";

const router = Router();

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
        memberships: { select: { organizationId: true } },
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
 *                       lat:
 *                         type: number
 *                       lng:
 *                         type: number
 *                       count:
 *                         type: integer
 *                       severity:
 *                         type: string
 *                         enum: [high, medium, low]
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get("/attack-origins", async (req: Request, res: Response) => {
  console.log("[Attack Origins] Endpoint hit - /api/logs/attack-origins");
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      console.log("[Attack Origins] No token provided");
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

    const hostFilter = req.query.host as string | undefined;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);

    // Build where clause
    const where: any = {};

    // For super_admin: show all logs (or filter by host if provided)
    // For regular users: only show logs from their organizations
    if (currentUser.role === "super_admin") {
      // Show all logs
    } else {
      // Regular user: only show logs from their organizations
      const userOrganizationIds = currentUser.memberships.map(
        (m) => m.organizationId
      );

      if (userOrganizationIds.length === 0) {
        return res.json({ origins: [] });
      }

      where.organizationId = {
        in: userOrganizationIds,
      };
    }

    // Apply host filter (matches the host and its subdomains, nothing else)
    if (hostFilter) {
      where.AND = [buildHostCondition(hostFilter)];
    }

    // Fetch all logs (no time filter - show all attack origins)
    // Use a large limit to ensure we get all logs, or remove limit entirely
    const logs = await prisma.log.findMany({
      where,
      select: {
        clientIp: true,
        severity: true,
        timestamp: true,
      },
      orderBy: {
        timestamp: 'desc', // Get most recent logs first
      },
      // Remove any implicit limits - get ALL logs
    });

    console.log(`[Attack Origins] Fetched ${logs.length} logs from database`);

    // Group by country and calculate stats
    const countryMap = new Map<
      string,
      {
        count: number;
        severities: string[];
        lat: number;
        lng: number;
        sampleIp: string;
        allIps: Set<string>; // Track all IPs for debugging
      }
    >();

    // Process ALL logs and their clientIp values
    let processedCount = 0;
    let skippedCount = 0;
    
    // Extract all unique IPs first
    const uniqueIPs = new Set<string>();
    const ipToLogs = new Map<string, typeof logs>();
    
    for (const log of logs) {
      const ip = log.clientIp;
      
      // Skip if IP is null or empty
      if (!ip || ip.trim() === '') {
        skippedCount++;
        continue;
      }

      uniqueIPs.add(ip);
      if (!ipToLogs.has(ip)) {
        ipToLogs.set(ip, []);
      }
      ipToLogs.get(ip)!.push(log);
    }

    console.log(`[Attack Origins] Found ${uniqueIPs.size} unique IPs to geolocate`);

    // Batch geolocate all IPs using the API
    const ipLocations = await getLocationsFromIPs(Array.from(uniqueIPs));

    // Process logs with their geolocated data
    for (const log of logs) {
      const ip = log.clientIp;
      
      // Skip if IP is null or empty
      if (!ip || ip.trim() === '') {
        continue;
      }

      const location = ipLocations.get(ip);
      if (!location) {
        console.warn(`[Attack Origins] No location found for IP: ${ip}`);
        continue;
      }

      const country = location.country;

      // Debug logging for UK IPs specifically
      if (ip === '194.88.100.170' || country === 'United Kingdom' || country === 'GB') {
        console.log(`[Attack Origins] Processing UK IP: ${ip}, Country: ${country}, Lat: ${location.lat}, Lng: ${location.lng}`);
      }

      if (!countryMap.has(country)) {
        countryMap.set(country, {
          count: 0,
          severities: [],
          lat: location.lat,
          lng: location.lng,
          sampleIp: ip,
          allIps: new Set(),
        });
      }
      const entry = countryMap.get(country)!;
      entry.count++;
      entry.severities.push(log.severity);
      entry.allIps.add(ip); // Track this IP
      processedCount++;
    }
    
    console.log(`[Attack Origins] Processed ${processedCount} logs, skipped ${skippedCount} empty IPs`);

    console.log(`[Attack Origins] Grouped into ${countryMap.size} countries`);
    console.log(`[Attack Origins] Countries found:`, Array.from(countryMap.keys()));
    
    // Log details for each country to help debug
    countryMap.forEach((data, country) => {
      const ipList = Array.from(data.allIps).slice(0, 5);
      console.log(`[Attack Origins] Country: "${country}", Count: ${data.count}, Sample IPs: ${ipList.join(', ')}${data.allIps.size > 5 ? ` (+${data.allIps.size - 5} more)` : ''}`);
    });

    // Convert to array and calculate severity
    const origins = Array.from(countryMap.entries())
      .map(([country, data]) => {
        // Determine overall severity (highest severity from logs)
        const hasCritical = data.severities.some((s) => s === "CRITICAL");
        const hasHigh = data.severities.some((s) => s === "HIGH");
        const hasMedium = data.severities.some((s) => s === "MEDIUM");

        let severity: "high" | "medium" | "low" = "low";
        if (hasCritical || hasHigh) {
          severity = "high";
        } else if (hasMedium) {
          severity = "medium";
        }

        return {
          ip: data.sampleIp, // Keep IP for reference, but data is grouped by country
          country: country,
          lat: data.lat,
          lng: data.lng,
          count: data.count,
          severity,
        };
      })
      .filter((origin) => {
        // Filter out local IPs only (they have country "Local" and coordinates 0,0)
        // Keep "Unknown" countries and all other countries
        return origin.country !== "Local";
      })
      .sort((a, b) => b.count - a.count) // Sort by count descending
      .slice(0, limit);

    res.json({ origins });
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
