import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import { wafAgentService } from "../services/wafAgent";
import { normalizeDomain } from "../utils/normalizeDomain";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Domain WAF
 *   description: Domain WAF status management endpoints
 */

/**
 * Helper function to verify user has access to organization
 */
async function verifyOrganizationAccess(
  userId: string,
  organizationId: string
): Promise<{ hasAccess: boolean; isAdmin: boolean }> {
  // Check if user is super_admin
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { role: true },
  });

  if (user?.role === "super_admin") {
    return { hasAccess: true, isAdmin: true };
  }

  // Check if user is a member of the organization with admin role
  const membership = await prisma.organizationMember.findFirst({
    where: {
      userId,
      organizationId,
      status: "verified",
      role: "admin",
    },
  });

  return {
    hasAccess: !!membership,
    isAdmin: !!membership,
  };
}

/**
 * @swagger
 * /api/organizations/{id}/waf-status:
 *   get:
 *     summary: Get WAF status for all domains in an organization
 *     tags: [Domain WAF]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Organization ID
 *     responses:
 *       200:
 *         description: WAF status for all domains
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 organizationId:
 *                   type: string
 *                   format: uuid
 *                 domains:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       domain:
 *                         type: string
 *                       wafEnabled:
 *                         type: boolean
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - User doesn't have access to this organization
 *       404:
 *         description: Organization not found
 *       500:
 *         description: Server error
 */
router.get("/:id/waf-status", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id } = req.params;

    // Verify organization exists
    const organization = await prisma.organization.findUnique({
      where: { id },
      select: { id: true, domains: true },
    });

    if (!organization) {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    // Verify user has access
    const { hasAccess } = await verifyOrganizationAccess(user.id, id);
    if (!hasAccess) {
      return res.status(403).json({
        message: "You don't have access to this organization",
      });
    }

    // Get all WAF statuses for this organization
    const wafStatuses = await prisma.domainWAFStatus.findMany({
      where: { organizationId: id },
      select: {
        domain: true,
        wafEnabled: true,
      },
    });

    // Create a map of domain -> wafEnabled
    const statusMap = new Map(
      wafStatuses.map((s) => [s.domain, s.wafEnabled])
    );

    // Build response with all domains (including those without status records)
    const domains = organization.domains.map((domain) => ({
      domain,
      wafEnabled: statusMap.get(domain) ?? true, // Default to true if no record exists
    }));

    res.json({
      organizationId: id,
      domains,
    });
  } catch (error) {
    console.error("Error fetching WAF status:", error);
    res.status(500).json({
      message: "Failed to fetch WAF status",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/waf-status/toggle:
 *   post:
 *     summary: Toggle WAF status for a specific domain
 *     tags: [Domain WAF]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Organization ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - domain
 *               - enabled
 *             properties:
 *               domain:
 *                 type: string
 *                 description: Domain name to toggle
 *               enabled:
 *                 type: boolean
 *                 description: WAF enabled status (true = enabled, false = disabled)
 *     responses:
 *       200:
 *         description: WAF status updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 domain:
 *                   type: string
 *                 wafEnabled:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       400:
 *         description: Invalid input or domain doesn't belong to organization
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - User doesn't have admin access
 *       404:
 *         description: Organization not found
 *       500:
 *         description: Server error
 */
router.post("/:id/waf-status/toggle", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from database (include role for authorization check)
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id } = req.params;
    const { domain, enabled } = req.body;

    // Validate input
    if (!domain || typeof domain !== "string") {
      return res.status(400).json({
        message: "Domain is required and must be a string",
      });
    }

    if (typeof enabled !== "boolean") {
      return res.status(400).json({
        message: "Enabled must be a boolean",
      });
    }

    // Check if user is super_admin (can toggle any domain)
    const isSuperAdmin = user.role === "super_admin";

    // Verify organization exists and get domains
    const organization = await prisma.organization.findUnique({
      where: { id },
      select: { id: true, domains: true },
    });

    if (!organization) {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    const normalizedDomain = normalizeDomain(domain);

    // Authorization logic:
    // - super_admin: can toggle any domain (skip organization check)
    // - org admin: can only toggle domains that belong to their organization
    if (!isSuperAdmin) {
      // For org admins: verify domain belongs to their organization
      if (!organization.domains.includes(normalizedDomain)) {
        return res.status(403).json({
          message: "Domain does not belong to your organization",
        });
      }

      // Verify user is admin of this organization
      const { hasAccess, isAdmin } = await verifyOrganizationAccess(
        user.id,
        id
      );
      if (!hasAccess || !isAdmin) {
        return res.status(403).json({
          message: "You must be an admin of this organization to toggle WAF status",
        });
      }
    }

    // Call WAF agent first to update nginx configuration
    try {
      console.log(
        `Calling WAF agent to ${enabled ? "enable" : "disable"} WAF for ${normalizedDomain}`
      );
      const agentResponse = await wafAgentService.toggleWAF(
        normalizedDomain,
        enabled
      );

      if (agentResponse.status !== "OK") {
        throw new Error(
          `WAF agent returned non-OK status: ${agentResponse.message}`
        );
      }

      console.log(
        `WAF agent successfully ${enabled ? "enabled" : "disabled"} WAF for ${normalizedDomain}`
      );
    } catch (agentError) {
      console.error("WAF agent error:", agentError);
      return res.status(502).json({
        message: "Failed to update WAF configuration on server",
        error:
          agentError instanceof Error
            ? agentError.message
            : "Unknown error from WAF agent",
        details:
          "The WAF agent could not update the nginx configuration. Database was not updated.",
      });
    }

    // Only update database if agent call was successful
    const wafStatus = await prisma.domainWAFStatus.upsert({
      where: {
        organizationId_domain: {
          organizationId: id,
          domain: normalizedDomain,
        },
      },
      update: {
        wafEnabled: enabled,
      },
      create: {
        organizationId: id,
        domain: normalizedDomain,
        wafEnabled: enabled,
      },
    });

    res.json({
      domain: wafStatus.domain,
      wafEnabled: wafStatus.wafEnabled,
      message: `WAF ${enabled ? "enabled" : "disabled"} for ${normalizedDomain}`,
    });
  } catch (error) {
    console.error("Error toggling WAF status:", error);
    res.status(500).json({
      message: "Failed to toggle WAF status",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/waf-status:
 *   put:
 *     summary: Bulk update WAF status for multiple domains
 *     tags: [Domain WAF]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Organization ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - domains
 *             properties:
 *               domains:
 *                 type: array
 *                 items:
 *                   type: object
 *                   required:
 *                     - domain
 *                     - enabled
 *                   properties:
 *                     domain:
 *                       type: string
 *                     enabled:
 *                       type: boolean
 *     responses:
 *       200:
 *         description: WAF statuses updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 organizationId:
 *                   type: string
 *                 domains:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       domain:
 *                         type: string
 *                       wafEnabled:
 *                         type: boolean
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization not found
 *       500:
 *         description: Server error
 */
router.put("/:id/waf-status", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from database (include role for authorization check)
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id } = req.params;
    const { domains } = req.body;

    // Validate input
    if (!Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({
        message: "Domains must be a non-empty array",
      });
    }

    // Check if user is super_admin (can toggle any domain)
    const isSuperAdmin = user.role === "super_admin";

    // Verify organization exists
    const organization = await prisma.organization.findUnique({
      where: { id },
      select: { id: true, domains: true },
    });

    if (!organization) {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    // Authorization logic:
    // - super_admin: can toggle any domain (skip organization check)
    // - org admin: can only toggle domains that belong to their organization
    if (!isSuperAdmin) {
      // Verify user is admin of this organization
      const { hasAccess, isAdmin } = await verifyOrganizationAccess(
        user.id,
        id
      );
      if (!hasAccess || !isAdmin) {
        return res.status(403).json({
          message: "You must be an admin of this organization to update WAF status",
        });
      }

      // Validate all domains belong to organization (for org admins only)
      const normalizedOrgDomains = organization.domains.map((d) =>
        d.toLowerCase().trim()
      );
      for (const item of domains) {
        if (!item.domain || typeof item.enabled !== "boolean") {
          return res.status(400).json({
            message: "Each domain item must have 'domain' (string) and 'enabled' (boolean)",
          });
        }

        const normalizedDomain = normalizeDomain(item.domain);
        if (!normalizedOrgDomains.includes(normalizedDomain)) {
          return res.status(403).json({
            message: `Domain ${normalizedDomain} does not belong to your organization`,
          });
        }
      }
    } else {
      // For super_admin: validate input format but skip organization check
      for (const item of domains) {
        if (!item.domain || typeof item.enabled !== "boolean") {
          return res.status(400).json({
            message: "Each domain item must have 'domain' (string) and 'enabled' (boolean)",
          });
        }
      }
    }

    // Call WAF agent for each domain first
    const agentErrors: Array<{ domain: string; error: string }> = [];
    for (const item of domains) {
      const normalizedDomain = normalizeDomain(item.domain);
      try {
        console.log(
          `Calling WAF agent to ${item.enabled ? "enable" : "disable"} WAF for ${normalizedDomain}`
        );
        const agentResponse = await wafAgentService.toggleWAF(
          normalizedDomain,
          item.enabled
        );

        if (agentResponse.status !== "OK") {
          agentErrors.push({
            domain: normalizedDomain,
            error: agentResponse.message || "Unknown error",
          });
        }
      } catch (agentError) {
        console.error(`WAF agent error for ${normalizedDomain}:`, agentError);
        agentErrors.push({
          domain: normalizedDomain,
          error:
            agentError instanceof Error
              ? agentError.message
              : "Unknown error from WAF agent",
        });
      }
    }

    // If any agent calls failed, return error without updating database
    if (agentErrors.length > 0) {
      return res.status(502).json({
        message: "Failed to update WAF configuration on server for some domains",
        errors: agentErrors,
        details:
          "The WAF agent could not update the nginx configuration for some domains. Database was not updated.",
      });
    }

    // Only update database if all agent calls were successful
    const updatePromises = domains.map((item) =>
      prisma.domainWAFStatus.upsert({
        where: {
          organizationId_domain: {
            organizationId: id,
            domain: item.domain.toLowerCase().trim(),
          },
        },
        update: {
          wafEnabled: item.enabled,
        },
        create: {
          organizationId: id,
          domain: item.domain.toLowerCase().trim(),
          wafEnabled: item.enabled,
        },
      })
    );

    await Promise.all(updatePromises);

    // Fetch updated statuses
    const updatedStatuses = await prisma.domainWAFStatus.findMany({
      where: { organizationId: id },
      select: {
        domain: true,
        wafEnabled: true,
      },
    });

    res.json({
      organizationId: id,
      domains: updatedStatuses,
    });
  } catch (error) {
    console.error("Error bulk updating WAF status:", error);
    res.status(500).json({
      message: "Failed to update WAF statuses",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

export { router as domainWafRoutes };

