import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabase, supabaseAdmin } from "../lib/supabase";
import {
  AUTH_EMAIL_TOKEN_PURPOSE,
  createAuthEmailToken,
  deleteAuthEmailToken,
  invalidateOtherAuthEmailTokens,
} from "../services/authEmailTokenService";
import {
  isAuthEmailConfigured,
  sendInvitationEmail,
} from "../services/authEmailService";
import {
  ensureSupabaseAuthUser,
  normalizeEmail,
} from "../services/authUserService";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Organizations
 *   description: Organization management endpoints
 */

/**
 * @swagger
 * /api/organizations:
 *   get:
 *     summary: Get all organizations
 *     tags: [Organizations]
 *     responses:
 *       200:
 *         description: List of organizations
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Organization'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get("/", async (req: Request, res: Response) => {
  try {
    const organizations = await prisma.organization.findMany({
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                fullName: true,
              },
            },
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json(organizations);
  } catch (error) {
    console.error("Error fetching organizations:", error);
    res.status(500).json({
      message: "Failed to fetch organizations",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/my:
 *   get:
 *     summary: Get organizations where current user is a member
 *     tags: [Organizations]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of user's organizations
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Organization'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get("/my", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token and get user
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

    // Get organizations where user is a member
    const memberships = await prisma.organizationMember.findMany({
      where: { userId: user.id },
      include: {
        organization: {
          include: {
            members: {
              include: {
                user: {
                  select: {
                    id: true,
                    email: true,
                    fullName: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    const organizations = memberships.map(
      (membership) => membership.organization
    );

    res.json(organizations);
  } catch (error) {
    console.error("Error fetching user organizations:", error);
    res.status(500).json({
      message: "Failed to fetch user organizations",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}:
 *   get:
 *     summary: Get organization by ID
 *     tags: [Organizations]
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
 *         description: Organization details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Organization'
 *       404:
 *         description: Organization not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get("/:id", async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const organization = await prisma.organization.findUnique({
      where: { id },
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                fullName: true,
              },
            },
          },
        },
      },
    });

    if (!organization) {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    res.json(organization);
  } catch (error) {
    console.error("Error fetching organization:", error);
    res.status(500).json({
      message: "Failed to fetch organization",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations:
 *   post:
 *     summary: Create a new organization
 *     tags: [Organizations]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - domains
 *               - adminEmail
 *             properties:
 *               name:
 *                 type: string
 *                 description: Organization name
 *               domains:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of domain names
 *               adminEmail:
 *                 type: string
 *                 format: email
 *                 description: Email of the admin to invite
 *     responses:
 *       201:
 *         description: Organization created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Organization'
 *       400:
 *         description: Invalid input
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post("/", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token and get user
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
    const creator = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
    });

    if (!creator) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { name, domains, adminEmail } = req.body;

    if (!name || !domains || !Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({
        message: "Name and domains (array) are required",
      });
    }

    if (!adminEmail || typeof adminEmail !== "string") {
      return res.status(400).json({
        message: "Admin email is required",
      });
    }

    if (!supabaseAdmin) {
      return res.status(500).json({
        message: "Supabase service role key not configured",
      });
    }

    if (!isAuthEmailConfigured()) {
      return res.status(503).json({
        message: "Email delivery is not configured",
      });
    }

    const normalizedAdminEmail = normalizeEmail(adminEmail);
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(normalizedAdminEmail)) {
      return res.status(400).json({
        message: "A valid admin email is required",
      });
    }

    let provisionedAuthUser:
      | Awaited<ReturnType<typeof ensureSupabaseAuthUser>>
      | undefined;
    let adminUserCreated = false;
    let mappedExistingUserId: string | undefined;
    let organizationId: string | undefined;
    let issuedTokenId: string | undefined;
    let deliveryCommitted = false;

    try {
      // This creates only an Auth identity. It never asks Supabase to send mail.
      provisionedAuthUser = await ensureSupabaseAuthUser({
        email: normalizedAdminEmail,
        userMetadata: { organization_name: name },
      });

      let adminUser = await prisma.user.findUnique({
        where: { email: normalizedAdminEmail },
      });

      if (
        adminUser?.authUserId &&
        adminUser.authUserId !== provisionedAuthUser.authUser.id
      ) {
        if (provisionedAuthUser.created) {
          await supabaseAdmin.auth.admin.deleteUser(provisionedAuthUser.authUser.id);
        }
        return res.status(409).json({
          message: "This email is linked to a different authentication account",
        });
      }

      if (!adminUser) {
        adminUser = await prisma.user.create({
          data: {
            id: provisionedAuthUser.authUser.id,
            authUserId: provisionedAuthUser.authUser.id,
            email: normalizedAdminEmail,
            fullName: null,
          },
        });
        adminUserCreated = true;
      } else if (!adminUser.authUserId) {
        adminUser = await prisma.user.update({
          where: { id: adminUser.id },
          data: { authUserId: provisionedAuthUser.authUser.id },
        });
        mappedExistingUserId = adminUser.id;
      }

      const created = await prisma.$transaction(async (tx) => {
        const organization = await tx.organization.create({
          data: {
            name,
            domains,
            ownerEmail: null,
            status: "pending",
          },
        });

        const membership = await tx.organizationMember.create({
          data: {
            userId: adminUser.id,
            organizationId: organization.id,
            role: "admin",
            status: "pending",
          },
        });

        return { organization, membership };
      });
      organizationId = created.organization.id;

      // Complete all database reads before handing the message to SMTP. Once
      // SMTP accepts it, destructive rollback would make the delivered link dead.
      const createdOrg = await prisma.organization.findUnique({
        where: { id: created.organization.id },
        include: {
          members: {
            include: {
              user: {
                select: {
                  id: true,
                  email: true,
                  fullName: true,
                },
              },
            },
          },
        },
      });
      if (!createdOrg) {
        throw new Error("Created organization could not be reloaded");
      }

      const issued = await createAuthEmailToken({
        purpose: AUTH_EMAIL_TOKEN_PURPOSE.INVITATION,
        email: normalizedAdminEmail,
        authUserId: provisionedAuthUser.authUser.id,
        organizationMemberId: created.membership.id,
        requiresPassword: provisionedAuthUser.requiresPassword,
      });
      issuedTokenId = issued.record.id;

      const delivery = await sendInvitationEmail({
        to: normalizedAdminEmail,
        token: issued.token,
        organizationName: name,
        role: "admin",
        requiresPassword: provisionedAuthUser.requiresPassword,
      });

      if (!delivery.success) {
        throw new Error(delivery.error || "SMTP delivery failed");
      }
      deliveryCommitted = true;

      try {
        await invalidateOtherAuthEmailTokens(issued.record);
      } catch (error) {
        console.error("Invitation sent but older tokens could not be invalidated:", error);
      }

      return res.status(201).json(createdOrg);
    } catch (invitationError) {
      console.error("Failed to create organization invitation:", invitationError);
      const prismaCode = (invitationError as { code?: string }).code;

      if (deliveryCommitted) {
        if (!res.headersSent) {
          return res.status(500).json({
            message: "The organization and invitation were created, but the response could not be completed",
          });
        }
        return;
      }

      if (issuedTokenId) {
        await deleteAuthEmailToken(issuedTokenId).catch(() => undefined);
      }
      if (organizationId) {
        await prisma.organization
          .delete({ where: { id: organizationId } })
          .catch(() => undefined);
      }
      if (adminUserCreated && provisionedAuthUser) {
        await prisma.user
          .delete({ where: { id: provisionedAuthUser.authUser.id } })
          .catch(() => undefined);
      }
      if (mappedExistingUserId && provisionedAuthUser?.created) {
        await prisma.user
          .updateMany({
            where: {
              id: mappedExistingUserId,
              authUserId: provisionedAuthUser.authUser.id,
            },
            data: { authUserId: null },
          })
          .catch(() => undefined);
      }
      if (provisionedAuthUser?.created) {
        await supabaseAdmin.auth.admin
          .deleteUser(provisionedAuthUser.authUser.id)
          .catch(() => undefined);
      }

      if (prismaCode === "P2002") {
        return res.status(409).json({
          message: "Organization with this name or domain already exists",
        });
      }

      return res.status(organizationId ? 502 : 500).json({
        message: organizationId
          ? "The organization was not created because the invitation email could not be delivered"
          : "Failed to create organization",
      });
    }
  } catch (error: any) {
    console.error("Error creating organization:", error);

    if (error.code === "P2002") {
      return res.status(409).json({
        message: "Organization with this name or domain already exists",
      });
    }

    res.status(500).json({
      message: "Failed to create organization",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}:
 *   put:
 *     summary: Update organization by ID
 *     tags: [Organizations]
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
 *             properties:
 *               name:
 *                 type: string
 *                 description: Organization name
 *               domains:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of domain names
 *               status:
 *                 type: string
 *                 enum: [active, pending, suspended, disabled]
 *                 description: Organization status
 *     responses:
 *       200:
 *         description: Organization updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Organization'
 *       400:
 *         description: Invalid input
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Organization not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.put("/:id", async (req: Request, res: Response) => {
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

    const { id } = req.params;
    const { name, domains, status } = req.body;

    // Validate status if provided
    if (
      status &&
      !["active", "pending", "suspended", "disabled"].includes(status)
    ) {
      return res.status(400).json({
        message: "Status must be one of: active, pending, suspended, disabled",
      });
    }

    // Validate domains if provided
    if (domains && (!Array.isArray(domains) || domains.length === 0)) {
      return res.status(400).json({
        message: "Domains must be a non-empty array",
      });
    }

    const organization = await prisma.organization.update({
      where: { id },
      data: {
        ...(name && { name }),
        ...(domains && { domains }),
        ...(status && { status }),
      },
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                fullName: true,
              },
            },
          },
        },
      },
    });

    res.json(organization);
  } catch (error: any) {
    console.error("Error updating organization:", error);

    if (error.code === "P2025") {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    res.status(500).json({
      message: "Failed to update organization",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}:
 *   delete:
 *     summary: Delete organization by ID
 *     tags: [Organizations]
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
 *         description: Organization deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Organization deleted successfully
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Organization not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.delete("/:id", async (req: Request, res: Response) => {
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

    const { id } = req.params;

    await prisma.organization.delete({
      where: { id },
    });

    res.json({
      message: "Organization deleted successfully",
    });
  } catch (error: any) {
    console.error("Error deleting organization:", error);

    if (error.code === "P2025") {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    res.status(500).json({
      message: "Failed to delete organization",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

export { router as organizationRoutes };
