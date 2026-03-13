import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import { wafAgentService } from "../services/wafAgent";
import { getLocationFromIP } from "../utils/ipGeolocation";
import { COUNTRY_CODE_TO_NAME } from "../constants/countryCodes";
import crypto from "crypto";

const router = Router();

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * @swagger
 * tags:
 *   name: IP Ban
 *   description: IP ban management endpoints
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
 * /api/organizations/{id}/ip-bans:
 *   get:
 *     summary: Get all IP bans for an organization
 *     tags: [IP Ban]
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
 *         description: List of IP bans
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization not found
 */
router.get("/:id/ip-bans", async (req: Request, res: Response) => {
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
      select: { id: true },
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

    // Get all IP bans for this organization
    const ipBans = await prisma.iPBan.findMany({
      where: { organizationId: id },
      orderBy: { bannedAt: "desc" },
    });

    res.json(ipBans);
  } catch (error) {
    console.error("Error fetching IP bans:", error);
    res.status(500).json({
      message: "Failed to fetch IP bans",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/ip-bans:
 *   post:
 *     summary: Ban an IP address for domains
 *     tags: [IP Ban]
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
 *               - ip
 *               - domains
 *             properties:
 *               ip:
 *                 type: string
 *                 description: IP address to ban
 *               domains:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of domains or ["*"] for all domains
 *               country:
 *                 type: string
 *                 description: ISO country code (optional)
 *               countryName:
 *                 type: string
 *                 description: Full country name (optional)
 *               reason:
 *                 type: string
 *                 description: Reason for ban (optional)
 *     responses:
 *       200:
 *         description: IP banned successfully
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization not found
 *       502:
 *         description: WAF agent error
 */
router.post("/:id/ip-bans", async (req: Request, res: Response) => {
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
    const { ip, domains, reason } = req.body;
    
    // Auto-detect country from IP
    let country: string | null = null;
    let countryName: string | null = null;
    
    try {
      const location = await getLocationFromIP(ip);
      
      // Use countryCode from API if available, otherwise try reverse lookup
      country = location.countryCode || null;
      
      if (!country && location.country !== "Unknown" && location.country !== "Local") {
        // Fallback: reverse lookup from country name
        for (const [code, name] of Object.entries(COUNTRY_CODE_TO_NAME)) {
          if (name === location.country) {
            country = code;
            break;
          }
        }
      }
      
      // Set country name (exclude Local and Unknown)
      if (location.country !== "Local" && location.country !== "Unknown") {
        countryName = location.country;
      }
    } catch (error) {
      console.warn(`Failed to get country for IP ${ip}:`, error);
      // Continue without country info
    }

    // Validate input
    if (!ip || typeof ip !== "string") {
      return res.status(400).json({
        message: "IP address is required and must be a string",
      });
    }

    // Basic IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      return res.status(400).json({
        message: "Invalid IP address format",
      });
    }

    if (!Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({
        message: "Domains must be a non-empty array",
      });
    }

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

    // Check if user is super_admin
    const isSuperAdmin = user.role === "super_admin";

    // Authorization logic
    if (!isSuperAdmin) {
      // Verify user is admin of this organization
      const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);
      if (!hasAccess || !isAdmin) {
        return res.status(403).json({
          message: "You must be an admin of this organization to ban IPs",
        });
      }

      // Validate domains belong to organization (unless "*")
      if (domains[0] !== "*") {
        const normalizedOrgDomains = organization.domains.map((d) =>
          d.toLowerCase().trim()
        );
        for (const domain of domains) {
          if (!normalizedOrgDomains.includes(domain.toLowerCase().trim())) {
            return res.status(403).json({
              message: `Domain ${domain} does not belong to your organization`,
            });
          }
        }
      }
    }

    // Resolve "*" to all organization domains
    let targetDomains = domains;
    if (domains.length === 1 && domains[0] === "*") {
      targetDomains = organization.domains;
    }

    // Call WAF agent to ban IP
    try {
      console.log(`Calling WAF agent to ban IP ${ip} for domains: ${targetDomains.join(", ")}`);
      const agentResponse = await wafAgentService.banIP(ip, targetDomains, "ban");

      if (!agentResponse.ok) {
        throw new Error(
          `WAF agent returned error: ${agentResponse.results.map((r) => r.message).join(", ")}`
        );
      }

      console.log(`WAF agent successfully banned IP ${ip}`);
    } catch (agentError) {
      console.error("WAF agent error:", agentError);
      return res.status(502).json({
        message: "Failed to ban IP on server",
        error:
          agentError instanceof Error
            ? agentError.message
            : "Unknown error from WAF agent",
        details:
          "The WAF agent could not ban the IP. Database was not updated.",
      });
    }

    // Only update database if agent call was successful
    const ipBan = await prisma.iPBan.upsert({
      where: {
        organizationId_ip: {
          organizationId: id,
          ip,
        },
      },
      update: {
        domains: targetDomains,
        country: country || null,
        countryName: countryName || null,
        reason: reason || null,
        updatedAt: new Date(),
      },
      create: {
        organizationId: id,
        ip,
        domains: targetDomains,
        country: country || null,
        countryName: countryName || null,
        reason: reason || "Manually added",
      },
    });

    res.json(ipBan);
  } catch (error) {
    console.error("Error banning IP:", error);
    res.status(500).json({
      message: "Failed to ban IP",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/ip-bans/{ipId}:
 *   delete:
 *     summary: Unban an IP address
 *     tags: [IP Ban]
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
 *         name: ipId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: IP ban ID
 *     responses:
 *       200:
 *         description: IP unbanned successfully
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: IP ban not found
 *       502:
 *         description: WAF agent error
 */
router.delete("/:id/ip-bans/:ipId", async (req: Request, res: Response) => {
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

    const { id, ipId } = req.params;

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
          message: "You must be an admin of this organization to unban IPs",
        });
      }
    }

    // Get IP ban record
    const ipBan = await prisma.iPBan.findUnique({
      where: { id: ipId },
    });

    if (!ipBan) {
      return res.status(404).json({
        message: "IP ban not found",
      });
    }

    // Verify IP ban belongs to organization
    if (ipBan.organizationId !== id) {
      return res.status(403).json({
        message: "IP ban does not belong to this organization",
      });
    }

    // Call WAF agent to unban IP
    try {
      console.log(`Calling WAF agent to unban IP ${ipBan.ip} for domains: ${ipBan.domains.join(", ")}`);
      const agentResponse = await wafAgentService.banIP(ipBan.ip, ipBan.domains, "unban");

      if (!agentResponse.ok) {
        throw new Error(
          `WAF agent returned error: ${agentResponse.results.map((r) => r.message).join(", ")}`
        );
      }

      console.log(`WAF agent successfully unbanned IP ${ipBan.ip}`);
    } catch (agentError) {
      console.error("WAF agent error:", agentError);
      return res.status(502).json({
        message: "Failed to unban IP on server",
        error:
          agentError instanceof Error
            ? agentError.message
            : "Unknown error from WAF agent",
        details:
          "The WAF agent could not unban the IP. Database was not updated.",
      });
    }

    // Only delete from database if agent call was successful
    await prisma.iPBan.delete({
      where: { id: ipId },
    });

    res.json({
      message: "IP unbanned successfully",
      ip: ipBan.ip,
    });
  } catch (error) {
    console.error("Error unbanning IP:", error);
    res.status(500).json({
      message: "Failed to unban IP",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/ip-geolocation/{ip}:
 *   get:
 *     summary: Get country information from IP address
 *     tags: [IP Ban]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: ip
 *         required: true
 *         schema:
 *           type: string
 *         description: IP address
 *     responses:
 *       200:
 *         description: Country information
 *       400:
 *         description: Invalid IP address
 *       401:
 *         description: Unauthorized
 */
router.get("/ip-geolocation/:ip", async (req: Request, res: Response) => {
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

    const { ip } = req.params;

    // Validate IP format
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      return res.status(400).json({
        message: "Invalid IP address format",
      });
    }

    // Get location from IP
    const location = await getLocationFromIP(ip);
    
    // Use countryCode from API if available, otherwise try reverse lookup
    let countryCode: string | null = location.countryCode || null;
    
    if (!countryCode && location.country !== "Unknown" && location.country !== "Local") {
      // Fallback: reverse lookup from country name
      for (const [code, name] of Object.entries(COUNTRY_CODE_TO_NAME)) {
        if (name === location.country) {
          countryCode = code;
          break;
        }
      }
    }

    res.json({
      country: countryCode || null,
      countryName: location.country !== "Local" && location.country !== "Unknown" ? location.country : null,
    });
  } catch (error) {
    console.error("Error getting IP geolocation:", error);
    res.status(500).json({
      message: "Failed to get IP geolocation",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/ip-bans/generate-token:
 *   post:
 *     summary: Generate a temporary token to ban an IP from a notification link
 *     tags: [IP Ban]
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
 *               - ip
 *               - domains
 *             properties:
 *               ip:
 *                 type: string
 *                 description: IP address to ban
 *               domains:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of domains or ["*"] for all domains
 *     responses:
 *       200:
 *         description: Token generated successfully
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 */
router.post("/:id/ip-bans/generate-token", async (req: Request, res: Response) => {
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
    const { ip, domains } = req.body;

    // Validate input
    if (!ip || typeof ip !== "string") {
      return res.status(400).json({
        message: "IP address is required and must be a string",
      });
    }

    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      return res.status(400).json({
        message: "Invalid IP address format",
      });
    }

    if (!Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({
        message: "Domains must be a non-empty array",
      });
    }

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

    // Check authorization
    const isSuperAdmin = user.role === "super_admin";
    if (!isSuperAdmin) {
      const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);
      if (!hasAccess || !isAdmin) {
        return res.status(403).json({
          message: "You must be an admin of this organization to generate ban tokens",
        });
      }

      // Validate domains belong to organization (unless "*")
      if (domains[0] !== "*") {
        const normalizedOrgDomains = organization.domains.map((d) =>
          d.toLowerCase().trim()
        );
        for (const domain of domains) {
          if (!normalizedOrgDomains.includes(domain.toLowerCase().trim())) {
            return res.status(403).json({
              message: `Domain ${domain} does not belong to your organization`,
            });
          }
        }
      }
    }

    // Generate secure random token
    const banToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Store token
    const tokenRecord = await prisma.iPBanToken.create({
      data: {
        organizationId: id,
        ip,
        domains,
        token: banToken,
        expiresAt,
      },
    });

    // Get frontend URL
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
    const banUrl = `${frontendUrl}/api/ip-bans/ban?token=${banToken}`;

    return res.json({
      token: banToken,
      banUrl,
      expiresAt: expiresAt.toISOString(),
    });
  } catch (error) {
    console.error("Error generating ban token:", error);
    res.status(500).json({
      message: "Failed to generate ban token",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

export const publicIPBanRouter = Router();

/**
 * @swagger
 * /api/ip-bans/ban:
 *   get:
 *     summary: Ban an IP using a temporary token (GET for email links, shows confirmation page)
 *     tags: [IP Ban]
 *   post:
 *     summary: Ban an IP using a temporary token (POST for API calls)
 *     tags: [IP Ban]
 *     parameters:
 *       - in: query
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Temporary ban token
 *     responses:
 *       200:
 *         description: IP banned successfully
 *       400:
 *         description: Invalid token or input
 *       404:
 *         description: Token not found or expired
 *       502:
 *         description: WAF agent error
 */
async function handleBanByToken(req: Request, res: Response) {
  try {
    const { token } = req.query;

    if (!token || typeof token !== "string") {
      return res.status(400).json({
        message: "Token is required",
      });
    }

    // Find token record
    const tokenRecord = await prisma.iPBanToken.findUnique({
      where: { token },
    });

    if (!tokenRecord) {
      return res.status(404).json({
        message: "Invalid or expired token",
      });
    }

    // Check if already used
    if (tokenRecord.usedAt) {
      return res.status(400).json({
        message: "This token has already been used",
      });
    }

    // Check if expired
    if (new Date() > tokenRecord.expiresAt) {
      return res.status(400).json({
        message: "Token has expired",
      });
    }

    // Get organization to resolve "*" domains
    const organization = await prisma.organization.findUnique({
      where: { id: tokenRecord.organizationId },
      select: { domains: true },
    });

    if (!organization) {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    // Resolve "*" to all organization domains
    let targetDomains = tokenRecord.domains;
    if (tokenRecord.domains.length === 1 && tokenRecord.domains[0] === "*") {
      targetDomains = organization.domains;
    }

    // Auto-detect country from IP
    let country: string | null = null;
    let countryName: string | null = null;

    try {
      const location = await getLocationFromIP(tokenRecord.ip);
      country = location.countryCode || null;

      if (!country && location.country !== "Unknown" && location.country !== "Local") {
        for (const [code, name] of Object.entries(COUNTRY_CODE_TO_NAME)) {
          if (name === location.country) {
            country = code;
            break;
          }
        }
      }

      if (location.country !== "Local" && location.country !== "Unknown") {
        countryName = location.country;
      }
    } catch (error) {
      console.warn(`Failed to get country for IP ${tokenRecord.ip}:`, error);
    }

    // Call WAF agent to ban IP
    try {
      console.log(`[Token Ban] Calling WAF agent to ban IP ${tokenRecord.ip} for domains: ${targetDomains.join(", ")}`);
      const agentResponse = await wafAgentService.banIP(tokenRecord.ip, targetDomains, "ban");

      if (!agentResponse.ok) {
        throw new Error(
          `WAF agent returned error: ${agentResponse.results.map((r) => r.message).join(", ")}`
        );
      }

      console.log(`[Token Ban] WAF agent successfully banned IP ${tokenRecord.ip}`);
    } catch (agentError) {
      console.error("[Token Ban] WAF agent error:", agentError);
      return res.status(502).json({
        message: "Failed to ban IP on server",
        error:
          agentError instanceof Error
            ? agentError.message
            : "Unknown error from WAF agent",
      });
    }

    // Mark token as used
    await prisma.iPBanToken.update({
      where: { id: tokenRecord.id },
      data: { usedAt: new Date() },
    });

    // Create or update IP ban record
    const ipBan = await prisma.iPBan.upsert({
      where: {
        organizationId_ip: {
          organizationId: tokenRecord.organizationId,
          ip: tokenRecord.ip,
        },
      },
      update: {
        domains: targetDomains,
        country: country || null,
        countryName: countryName || null,
        reason: "Banned from notification",
        updatedAt: new Date(),
      },
      create: {
        organizationId: tokenRecord.organizationId,
        ip: tokenRecord.ip,
        domains: targetDomains,
        country: country || null,
        countryName: countryName || null,
        reason: "Banned from notification",
      },
    });

    // If GET request, show HTML confirmation page
    if (req.method === "GET") {
      return res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IP Banned Successfully</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .container {
      background: white;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 500px;
    }
    .success-icon {
      font-size: 64px;
      margin-bottom: 20px;
    }
    h1 {
      color: #111827;
      margin: 0 0 10px;
    }
    p {
      color: #6b7280;
      margin: 10px 0;
    }
    .ip {
      font-family: monospace;
      background: #f3f4f6;
      padding: 8px 16px;
      border-radius: 6px;
      display: inline-block;
      margin: 10px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">✅</div>
    <h1>IP Address Banned</h1>
    <p>The IP address has been successfully banned.</p>
    <div class="ip">${ipBan.ip}</div>
    <p style="margin-top: 20px; font-size: 14px;">This IP will be blocked on: ${ipBan.domains.join(", ")}</p>
    <p style="margin-top: 30px; font-size: 12px; color: #9ca3af;">You can close this window.</p>
  </div>
</body>
</html>
      `);
    }

    // POST request returns JSON
    return res.json({
      message: "IP banned successfully",
      ip: ipBan.ip,
      domains: ipBan.domains,
    });
  } catch (error) {
    console.error("Error banning IP by token:", error);
    
    // If GET request, show error page
    if (req.method === "GET") {
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      return res.status(400).send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ban Failed</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
    }
    .container {
      background: white;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 500px;
    }
    .error-icon {
      font-size: 64px;
      margin-bottom: 20px;
    }
    h1 {
      color: #dc2626;
      margin: 0 0 10px;
    }
    p {
      color: #6b7280;
      margin: 10px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-icon">❌</div>
    <h1>Ban Failed</h1>
    <p>${escapeHtml(errorMsg)}</p>
    <p style="margin-top: 30px; font-size: 12px; color: #9ca3af;">The token may be invalid, expired, or already used.</p>
  </div>
</body>
</html>
      `);
    }

    res.status(500).json({
      message: "Failed to ban IP",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
}

publicIPBanRouter.get("/ban", handleBanByToken);
publicIPBanRouter.post("/ban", handleBanByToken);

export { router as ipBanRoutes };
