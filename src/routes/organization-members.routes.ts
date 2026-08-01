import { Router, Request, Response } from "express";
import type { Prisma } from "@prisma/client";
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

type InvitedMember = Prisma.OrganizationMemberGetPayload<{
  include: {
    user: {
      select: {
        id: true;
        email: true;
        fullName: true;
        disabled: true;
        lastLogin: true;
      };
    };
  };
}>;

/**
 * @swagger
 * tags:
 *   name: Organization Members
 *   description: Organization member management endpoints
 */

/**
 * @swagger
 * /api/organization-members/my-organization:
 *   get:
 *     summary: Get all members of the current user's organization
 *     tags: [Organization Members]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of organization members
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 organization:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *                 members:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       userId:
 *                         type: string
 *                       organizationId:
 *                         type: string
 *                       role:
 *                         type: string
 *                       status:
 *                         type: string
 *                       user:
 *                         type: object
 *                         properties:
 *                           id:
 *                             type: string
 *                           email:
 *                             type: string
 *                           fullName:
 *                             type: string
 *                             nullable: true
 *                           disabled:
 *                             type: boolean
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get("/my-organization", async (req: Request, res: Response) => {
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
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      include: {
        memberships: {
          where: {
            status: "verified",
          },
          include: {
            organization: true,
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Get the first verified organization (admin should only be in one org)
    const membership = user.memberships[0];

    if (!membership) {
      return res.status(404).json({
        message: "No organization found for this user",
      });
    }

    // Get all members of this organization
    const members = await prisma.organizationMember.findMany({
      where: {
        organizationId: membership.organizationId,
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            fullName: true,
            disabled: true,
            lastLogin: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json({
      organization: {
        id: membership.organization.id,
        name: membership.organization.name,
      },
      members: members.map((m) => ({
        id: m.id,
        userId: m.userId,
        organizationId: m.organizationId,
        role: m.role,
        status: m.status,
        user: {
          id: m.user.id,
          email: m.user.email,
          fullName: m.user.fullName,
          disabled: m.user.disabled,
          lastLogin: m.user.lastLogin?.toISOString() || null,
        },
      })),
    });
  } catch (error) {
    console.error("Error fetching organization members:", error);
    res.status(500).json({
      message: "Failed to fetch organization members",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organization-members/{memberId}:
 *   delete:
 *     summary: Remove a member from the requester's organization
 *     tags: [Organization Members]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: memberId
 *         required: true
 *         schema:
 *           type: string
 *         description: Organization membership ID
 *     responses:
 *       200:
 *         description: Member removed successfully
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Membership not found
 *       500:
 *         description: Server error
 */
router.delete("/:memberId", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.slice("Bearer ".length).trim()
      : undefined;

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

    const identityFilters: Prisma.UserWhereInput[] = [
      { authUserId: supabaseUser.id },
    ];
    if (supabaseUser.email) {
      identityFilters.push({
        authUserId: null,
        email: normalizeEmail(supabaseUser.email),
      });
    }

    const currentUser = await prisma.user.findFirst({
      where: { OR: identityFilters },
      select: { id: true },
    });

    if (!currentUser) {
      return res.status(403).json({
        message: "You are not authorized to delete organization members",
      });
    }

    const deletionResult = await prisma.$transaction(async (tx) => {
      const targetMembership = await tx.organizationMember.findUnique({
        where: { id: req.params.memberId },
        select: {
          id: true,
          userId: true,
          organizationId: true,
        },
      });

      if (!targetMembership) {
        return {
          status: 404 as const,
          message: "Organization member not found",
        };
      }

      const requesterMembership = await tx.organizationMember.findFirst({
        where: {
          userId: currentUser.id,
          organizationId: targetMembership.organizationId,
          role: "admin",
          status: "verified",
        },
        select: { id: true },
      });

      if (!requesterMembership) {
        return {
          status: 403 as const,
          message: "Only verified organization admins can delete this member",
        };
      }

      if (targetMembership.userId === currentUser.id) {
        return {
          status: 403 as const,
          message: "You cannot delete your own organization membership",
        };
      }

      await tx.authEmailToken.deleteMany({
        where: { organizationMemberId: targetMembership.id },
      });
      const deletedMembership = await tx.organizationMember.deleteMany({
        where: { id: targetMembership.id },
      });

      if (deletedMembership.count === 0) {
        return {
          status: 404 as const,
          message: "Organization member not found",
        };
      }

      return {
        status: 200 as const,
        message: "User deleted successfully",
      };
    });

    return res
      .status(deletionResult.status)
      .json({ message: deletionResult.message });
  } catch (error) {
    console.error("Error deleting organization member:", error);
    return res.status(500).json({ message: "Failed to delete user" });
  }
});

/**
 * @swagger
 * /api/organization-members/{userId}/toggle-disabled:
 *   patch:
 *     summary: Toggle disabled status of a user
 *     tags: [Organization Members]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       200:
 *         description: User disabled status updated
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
/**
 * @swagger
 * /api/organization-members/invite:
 *   post:
 *     summary: Invite a user to the current user's organization
 *     tags: [Organization Members]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - role
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               role:
 *                 type: string
 *                 enum: [admin, viewer]
 *     responses:
 *       201:
 *         description: User invited successfully
 *       400:
 *         description: Bad request
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden (not admin of organization)
 *       500:
 *         description: Server error
 */
router.post("/invite", async (req: Request, res: Response) => {
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

    // Get current user from our database
    const currentUser = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      include: {
        memberships: {
          where: {
            status: "verified",
          },
          include: {
            organization: true,
          },
        },
      },
    });

    if (!currentUser) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Get the first verified organization
    const membership = currentUser.memberships[0];

    if (!membership) {
      return res.status(404).json({
        message: "No organization found for this user",
      });
    }

    // Check if user is admin (only admins can invite)
    if (membership.role !== "admin") {
      return res.status(403).json({
        message: "Only admins can invite users to the organization",
      });
    }

    const { email, role } = req.body;

    if (!email || typeof email !== "string" || !role) {
      return res.status(400).json({
        message: "Email and role are required",
      });
    }

    if (!["admin", "viewer"].includes(role)) {
      return res.status(400).json({
        message: "Role must be 'admin' or 'viewer'",
      });
    }

    const normalizedEmail = normalizeEmail(email);
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(normalizedEmail)) {
      return res.status(400).json({ message: "A valid email is required" });
    }

    // Check if user is already a member of this organization
    const existingMember = await prisma.organizationMember.findFirst({
      where: {
        organizationId: membership.organizationId,
        user: {
          email: normalizedEmail,
        },
      },
    });

    if (existingMember) {
      return res.status(409).json({
        message: "User is already a member of this organization",
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

    let provisionedAuthUser:
      | Awaited<ReturnType<typeof ensureSupabaseAuthUser>>
      | undefined;
    let targetUserCreated = false;
    let mappedExistingUserId: string | undefined;
    let newMemberId: string | undefined;
    let issuedTokenId: string | undefined;
    let newMember!: InvitedMember;

    try {
      provisionedAuthUser = await ensureSupabaseAuthUser({
        email: normalizedEmail,
        userMetadata: {
          organization_name: membership.organization.name,
        },
      });

      let targetUser = await prisma.user.findUnique({
        where: { email: normalizedEmail },
      });

      if (
        targetUser?.authUserId &&
        targetUser.authUserId !== provisionedAuthUser.authUser.id
      ) {
        if (provisionedAuthUser.created) {
          await supabaseAdmin.auth.admin.deleteUser(provisionedAuthUser.authUser.id);
        }
        return res.status(409).json({
          message: "This email is linked to a different authentication account",
        });
      }

      if (!targetUser) {
        targetUser = await prisma.user.create({
          data: {
            id: provisionedAuthUser.authUser.id,
            authUserId: provisionedAuthUser.authUser.id,
            email: normalizedEmail,
            fullName: null,
          },
        });
        targetUserCreated = true;
      } else if (!targetUser.authUserId) {
        targetUser = await prisma.user.update({
          where: { id: targetUser.id },
          data: { authUserId: provisionedAuthUser.authUser.id },
        });
        mappedExistingUserId = targetUser.id;
      }

      newMember = await prisma.organizationMember.create({
        data: {
          userId: targetUser.id,
          organizationId: membership.organizationId,
          role,
          status: "pending",
        },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              fullName: true,
              disabled: true,
              lastLogin: true,
            },
          },
        },
      });
      newMemberId = newMember.id;

      const issued = await createAuthEmailToken({
        purpose: AUTH_EMAIL_TOKEN_PURPOSE.INVITATION,
        email: normalizedEmail,
        authUserId: provisionedAuthUser.authUser.id,
        organizationMemberId: newMember.id,
        requiresPassword: provisionedAuthUser.requiresPassword,
      });
      issuedTokenId = issued.record.id;

      const delivery = await sendInvitationEmail({
        to: normalizedEmail,
        token: issued.token,
        organizationName: membership.organization.name,
        role,
        requiresPassword: provisionedAuthUser.requiresPassword,
      });

      if (!delivery.success) {
        throw new Error(delivery.error || "SMTP delivery failed");
      }

      try {
        await invalidateOtherAuthEmailTokens(issued.record);
      } catch (error) {
        console.error("Invitation sent but older tokens could not be invalidated:", error);
      }
    } catch (invitationError) {
      console.error("Failed to invite organization member:", invitationError);
      if (issuedTokenId) {
        await deleteAuthEmailToken(issuedTokenId).catch(() => undefined);
      }
      if (newMemberId) {
        await prisma.organizationMember
          .delete({ where: { id: newMemberId } })
          .catch(() => undefined);
      }
      if (targetUserCreated && provisionedAuthUser) {
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

      return res.status(502).json({
        message: "The user was not invited because the email could not be delivered",
      });
    }

    res.status(201).json({
      message: "User invited successfully",
      member: {
        id: newMember.id,
        userId: newMember.userId,
        organizationId: newMember.organizationId,
        role: newMember.role,
        status: newMember.status,
        user: {
          id: newMember.user.id,
          email: newMember.user.email,
          fullName: newMember.user.fullName,
          disabled: newMember.user.disabled,
          lastLogin: newMember.user.lastLogin?.toISOString() || null,
        },
      },
    });
  } catch (error) {
    console.error("Error inviting user:", error);
    res.status(500).json({
      message: "Failed to invite user",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/** Resend an app-managed invitation email for one pending membership. */
router.post("/:memberId/resend-invitation", async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);
    if (error || !supabaseUser?.email) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    const currentUser = await prisma.user.findUnique({
      where: { email: normalizeEmail(supabaseUser.email) },
      include: {
        memberships: {
          where: { status: "verified", role: "admin" },
          select: { organizationId: true },
        },
      },
    });
    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    const pendingMembership = await prisma.organizationMember.findUnique({
      where: { id: req.params.memberId },
      include: { user: true, organization: true },
    });
    if (!pendingMembership) {
      return res.status(404).json({ message: "Invitation not found" });
    }
    if (
      !currentUser.memberships.some(
        (item) => item.organizationId === pendingMembership.organizationId
      )
    ) {
      return res.status(403).json({
        message: "Only organization admins can resend this invitation",
      });
    }
    if (pendingMembership.status !== "pending") {
      return res.status(409).json({ message: "This invitation is no longer pending" });
    }
    if (!supabaseAdmin) {
      return res.status(500).json({
        message: "Supabase service role key not configured",
      });
    }
    if (!isAuthEmailConfigured()) {
      return res.status(503).json({ message: "Email delivery is not configured" });
    }

    const provisioned = await ensureSupabaseAuthUser({
      email: pendingMembership.user.email,
      userMetadata: {
        organization_name: pendingMembership.organization.name,
      },
    });
    if (
      pendingMembership.user.authUserId &&
      pendingMembership.user.authUserId !== provisioned.authUser.id
    ) {
      if (provisioned.created) {
        await supabaseAdmin.auth.admin.deleteUser(provisioned.authUser.id);
      }
      return res.status(409).json({
        message: "This email is linked to a different authentication account",
      });
    }
    if (!pendingMembership.user.authUserId) {
      await prisma.user.update({
        where: { id: pendingMembership.user.id },
        data: { authUserId: provisioned.authUser.id },
      });
    }

    const issued = await createAuthEmailToken({
      purpose: AUTH_EMAIL_TOKEN_PURPOSE.INVITATION,
      email: pendingMembership.user.email,
      authUserId: provisioned.authUser.id,
      organizationMemberId: pendingMembership.id,
      requiresPassword: provisioned.requiresPassword,
    });

    const delivery = await sendInvitationEmail({
      to: pendingMembership.user.email,
      token: issued.token,
      organizationName: pendingMembership.organization.name,
      role: pendingMembership.role,
      requiresPassword: provisioned.requiresPassword,
    });

    if (!delivery.success) {
      await deleteAuthEmailToken(issued.record.id).catch(() => undefined);
      console.error("Failed to resend invitation email:", delivery.error);
      return res.status(502).json({
        message: "The invitation email could not be delivered",
      });
    }

    try {
      await invalidateOtherAuthEmailTokens(issued.record);
    } catch (error) {
      console.error("Invitation resent but older tokens could not be invalidated:", error);
    }
    return res.json({ message: "Invitation email sent successfully" });
  } catch (error) {
    console.error("Error resending invitation:", error);
    return res.status(500).json({ message: "Failed to resend invitation" });
  }
});

router.patch("/:userId/toggle-disabled", async (req: Request, res: Response) => {
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

    const { userId } = req.params;

    // Get the user to toggle
    const targetUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!targetUser) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Toggle disabled status
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        disabled: !targetUser.disabled,
      },
      select: {
        id: true,
        email: true,
        fullName: true,
        disabled: true,
      },
    });

    res.json({
      message: `User ${updatedUser.disabled ? "disabled" : "enabled"} successfully`,
      user: updatedUser,
    });
  } catch (error) {
    console.error("Error toggling user disabled status:", error);
    res.status(500).json({
      message: "Failed to toggle user disabled status",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

export { router as organizationMembersRoutes };


