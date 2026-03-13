import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import { geoAgentService } from "../services/geoAgent";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Geo Access Control
 *   description: Geo location access control management endpoints
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
 * /api/organizations/{id}/geo-access:
 *   get:
 *     summary: Get geo access control settings for all domains in an organization
 *     tags: [Geo Access Control]
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
 *         description: Geo access control settings for all domains
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 organizationId:
 *                   type: string
 *                   format: uuid
 *                 settings:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/GeoAccessControl'
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization not found
 */
router.get("/:id/geo-access", async (req: Request, res: Response) => {
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

    // Get all geo access settings for this organization
    const geoSettings = await prisma.geoAccessControl.findMany({
      where: { organizationId: id },
      orderBy: { domain: "asc" },
    });

    res.json({
      organizationId: id,
      settings: geoSettings,
    });
  } catch (error) {
    console.error("Error fetching geo access settings:", error);
    res.status(500).json({
      message: "Failed to fetch geo access settings",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/geo-access/{domain}:
 *   get:
 *     summary: Get geo access control settings for a specific domain
 *     tags: [Geo Access Control]
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
 *       - in: path
 *         name: domain
 *         required: true
 *         schema:
 *           type: string
 *         description: Domain name or "All" for all domains
 *     responses:
 *       200:
 *         description: Geo access control settings
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GeoAccessControl'
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization or settings not found
 */
router.get("/:id/geo-access/:domain", async (req: Request, res: Response) => {
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

    const { id, domain } = req.params;
    const normalizedDomain = domain === "All" ? "*" : domain.toLowerCase().trim();

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

    // Validate domain belongs to organization (unless "*" or "All")
    if (normalizedDomain !== "*") {
      const normalizedOrgDomains = organization.domains.map((d) =>
        d.toLowerCase().trim()
      );
      if (!normalizedOrgDomains.includes(normalizedDomain)) {
        return res.status(403).json({
          message: "Domain does not belong to this organization",
        });
      }
    }

    // Get geo access settings for this domain
    const geoSetting = await prisma.geoAccessControl.findUnique({
      where: {
        organizationId_domain: {
          organizationId: id,
          domain: normalizedDomain,
        },
      },
    });

    if (!geoSetting) {
      return res.status(404).json({
        message: "Geo access settings not found for this domain",
      });
    }

    res.json(geoSetting);
  } catch (error) {
    console.error("Error fetching geo access settings:", error);
    res.status(500).json({
      message: "Failed to fetch geo access settings",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/geo-access:
 *   post:
 *     summary: Create or update geo access control settings
 *     tags: [Geo Access Control]
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
 *               - mode
 *             properties:
 *               domain:
 *                 type: string
 *                 description: Domain name or "All" for all domains
 *               mode:
 *                 type: string
 *                 enum: [allow-all, allow-only, ban-specific]
 *                 description: Filter mode
 *               allowedCountries:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: ISO-3166-1 alpha-2 country codes for allow list
 *               deniedCountries:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: ISO-3166-1 alpha-2 country codes for deny list
 *     responses:
 *       200:
 *         description: Geo access settings created/updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GeoAccessControl'
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization not found
 */
router.post("/:id/geo-access", async (req: Request, res: Response) => {
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
      select: { id: true, role: true },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id } = req.params;
    const { domain, mode, allowedCountries = [], deniedCountries = [] } = req.body;

    // Validate input
    if (!domain || typeof domain !== "string") {
      return res.status(400).json({
        message: "Domain is required and must be a string",
      });
    }

    if (!mode || !["allow-all", "allow-only", "ban-specific"].includes(mode)) {
      return res.status(400).json({
        message: 'Mode must be one of: "allow-all", "allow-only", "ban-specific"',
      });
    }

    if (!Array.isArray(allowedCountries) || !Array.isArray(deniedCountries)) {
      return res.status(400).json({
        message: "allowedCountries and deniedCountries must be arrays",
      });
    }

    // Validate country codes (ISO-3166-1 alpha-2)
    const countryCodeRegex = /^[A-Z]{2}$/;
    const allCountries = [...allowedCountries, ...deniedCountries];
    for (const code of allCountries) {
      if (typeof code !== "string" || !countryCodeRegex.test(code)) {
        return res.status(400).json({
          message: `Invalid country code: ${code}. Must be uppercase ISO-3166-1 alpha-2 (e.g., "US", "ET")`,
        });
      }
    }

    // Check if user is super_admin
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

    const normalizedDomain = domain === "All" ? "*" : domain.toLowerCase().trim();

    // Authorization logic
    if (!isSuperAdmin) {
      // Verify user is admin of this organization
      const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);
      if (!hasAccess || !isAdmin) {
        return res.status(403).json({
          message: "You must be an admin of this organization to manage geo access settings",
        });
      }

      // Validate domain belongs to organization (unless "*" or "All")
      if (normalizedDomain !== "*") {
        const normalizedOrgDomains = organization.domains.map((d) =>
          d.toLowerCase().trim()
        );
        if (!normalizedOrgDomains.includes(normalizedDomain)) {
          return res.status(403).json({
            message: "Domain does not belong to your organization",
          });
        }
      }
    }

    // Enforce mode-specific rules: clear opposite lists and remove intersections
    let finalAllowed: string[] = [];
    let finalDenied: string[] = [];

    if (mode === "allow-all") {
      // allow-all: both lists must be empty
      if (allowedCountries.length > 0 || deniedCountries.length > 0) {
        return res.status(400).json({
          message: "allow-all mode requires both allowedCountries and deniedCountries to be empty",
        });
      }
      finalAllowed = [];
      finalDenied = [];
    } else if (mode === "allow-only") {
      // allow-only: deniedCountries must be empty, validate allowedCountries
      if (deniedCountries.length > 0) {
        return res.status(400).json({
          message: "allow-only mode requires deniedCountries to be empty",
        });
      }
      if (allowedCountries.length === 0) {
        return res.status(400).json({
          message: "allow-only mode requires at least one country in allowedCountries",
        });
      }
      // Remove duplicates
      finalAllowed = [...new Set(allowedCountries)];
      finalDenied = [];
    } else if (mode === "ban-specific") {
      // ban-specific: allowedCountries must be empty, validate deniedCountries
      if (allowedCountries.length > 0) {
        return res.status(400).json({
          message: "ban-specific mode requires allowedCountries to be empty",
        });
      }
      if (deniedCountries.length === 0) {
        return res.status(400).json({
          message: "ban-specific mode requires at least one country in deniedCountries",
        });
      }
      // Remove duplicates
      finalAllowed = [];
      finalDenied = [...new Set(deniedCountries)];
    }

    // Final check: ensure no intersections (safety check)
    const intersection = finalAllowed.filter((code) => finalDenied.includes(code));
    if (intersection.length > 0) {
      return res.status(400).json({
        message: `Countries cannot be in both allowed and denied lists: ${intersection.join(", ")}`,
      });
    }

    // Sync with geo-agent first (before saving to database)
    // Note: The geo-agent manages a single global config, so we sync whenever settings are saved
    // For now, we sync for all domains. Later you can add logic to sync only for specific domains.
    try {
      console.log(
        `Syncing geo access settings to agent: mode=${mode}, allowed=${finalAllowed.length}, denied=${finalDenied.length}`
      );
      await geoAgentService.syncSettings(mode, finalAllowed, finalDenied);
      console.log("Geo agent sync completed successfully");
    } catch (agentError) {
      console.error("Geo agent sync error:", agentError);
      return res.status(502).json({
        message: "Failed to sync settings with geo agent",
        error:
          agentError instanceof Error
            ? agentError.message
            : "Unknown error from geo agent",
        details:
          "The geo agent could not update the nginx configuration. Database was not updated.",
      });
    }

    // Only update database if agent sync was successful
    const geoSetting = await prisma.geoAccessControl.upsert({
      where: {
        organizationId_domain: {
          organizationId: id,
          domain: normalizedDomain,
        },
      },
      update: {
        mode,
        allowedCountries: finalAllowed,
        deniedCountries: finalDenied,
      },
      create: {
        organizationId: id,
        domain: normalizedDomain,
        mode,
        allowedCountries: finalAllowed,
        deniedCountries: finalDenied,
      },
    });

    res.json(geoSetting);
  } catch (error) {
    console.error("Error saving geo access settings:", error);
    res.status(500).json({
      message: "Failed to save geo access settings",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/geo-access/{domain}:
 *   delete:
 *     summary: Delete geo access control settings for a domain
 *     tags: [Geo Access Control]
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
 *       - in: path
 *         name: domain
 *         required: true
 *         schema:
 *           type: string
 *         description: Domain name or "All" for all domains
 *     responses:
 *       200:
 *         description: Geo access settings deleted successfully
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization or settings not found
 */
router.delete("/:id/geo-access/:domain", async (req: Request, res: Response) => {
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
      select: { id: true, role: true },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id, domain } = req.params;
    const normalizedDomain = domain === "All" ? "*" : domain.toLowerCase().trim();

    // Verify organization exists
    const organization = await prisma.organization.findUnique({
      where: { id },
      select: { id: true },
    });

    if (!organization) {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    // Check if user is super_admin
    const isSuperAdmin = user.role === "super_admin";

    // Authorization logic
    if (!isSuperAdmin) {
      // Verify user is admin of this organization
      const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);
      if (!hasAccess || !isAdmin) {
        return res.status(403).json({
          message: "You must be an admin of this organization to delete geo access settings",
        });
      }
    }

    // Get settings before deleting (to sync removal with agent)
    const geoSetting = await prisma.geoAccessControl.findUnique({
      where: {
        organizationId_domain: {
          organizationId: id,
          domain: normalizedDomain,
        },
      },
    });

    if (!geoSetting) {
      return res.status(404).json({
        message: "Geo access settings not found for this domain",
      });
    }

    // If this was the active config, reset agent to allow-all (deny_only with empty list)
    // For now, we'll just delete from DB. You can add logic to sync agent if needed.
    // Note: Deleting settings means reverting to default (allow-all), so we could sync that.

    // Delete geo access settings
    await prisma.geoAccessControl.delete({
      where: {
        organizationId_domain: {
          organizationId: id,
          domain: normalizedDomain,
        },
      },
    });

    // Optionally sync agent to reset to allow-all
    // Uncomment if you want to reset agent when settings are deleted:
    // try {
    //   await geoAgentService.syncSettings("allow-all", [], []);
    // } catch (agentError) {
    //   console.error("Failed to reset geo agent after deletion:", agentError);
    //   // Continue anyway - deletion succeeded in DB
    // }

    res.json({
      message: "Geo access settings deleted successfully",
      domain: normalizedDomain,
    });
  } catch (error) {
    console.error("Error deleting geo access settings:", error);
    res.status(500).json({
      message: "Failed to delete geo access settings",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

export { router as geoAccessRoutes };
