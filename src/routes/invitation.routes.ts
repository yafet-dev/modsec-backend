import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabaseAdmin, supabase } from "../lib/supabase";
import {
  AUTH_EMAIL_TOKEN_PURPOSE,
  claimAuthEmailToken,
  findActiveAuthEmailToken,
  releaseAuthEmailTokenClaim,
} from "../services/authEmailTokenService";
import { normalizeEmail } from "../services/authUserService";

const router = Router();

function authUserIsConfirmed(user: {
  email_confirmed_at?: string | null;
  confirmed_at?: string | null;
}): boolean {
  return Boolean(user.email_confirmed_at || user.confirmed_at);
}

/**
 * @swagger
 * tags:
 *   name: Invitations
 *   description: Invitation acceptance endpoints
 */

/**
 * @swagger
 * /api/invitations/accept:
 *   post:
 *     summary: Accept an application-issued organization invitation
 *     tags: [Invitations]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *                 description: Invitation token from email
 *               password:
 *                 type: string
 *                 format: password
 *                 description: Required only for a first-time account
 *     responses:
 *       200:
 *         description: Invitation accepted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 user:
 *                   type: object
 *                 session:
 *                   type: object
 *       400:
 *         description: Invalid token or password
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
router.post("/validate", async (req: Request, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");

  try {
    const token = typeof req.body?.token === "string" ? req.body.token : "";
    if (!token) {
      return res.status(400).json({ message: "Invitation token is required" });
    }
    if (!supabaseAdmin) {
      return res.status(503).json({ message: "Authentication is not configured" });
    }

    const emailToken = await findActiveAuthEmailToken(
      token,
      AUTH_EMAIL_TOKEN_PURPOSE.INVITATION
    );
    if (!emailToken?.organizationMemberId) {
      return res.status(400).json({ message: "Invalid or expired invitation link" });
    }

    const membership = await prisma.organizationMember.findUnique({
      where: { id: emailToken.organizationMemberId },
      include: { user: true, organization: true },
    });
    if (
      !membership ||
      membership.status !== "pending" ||
      normalizeEmail(membership.user.email) !== emailToken.email ||
      (membership.user.authUserId &&
        membership.user.authUserId !== emailToken.authUserId)
    ) {
      return res.status(400).json({ message: "Invalid or expired invitation link" });
    }

    const { data: authData, error: authError } =
      await supabaseAdmin.auth.admin.getUserById(emailToken.authUserId);
    if (
      authError ||
      !authData.user ||
      normalizeEmail(authData.user.email || "") !== emailToken.email
    ) {
      return res.status(400).json({ message: "Invalid or expired invitation link" });
    }

    return res.json({
      email: membership.user.email,
      organizationName: membership.organization.name,
      role: membership.role,
      requiresPassword:
        emailToken.requiresPassword && !authUserIsConfirmed(authData.user),
      expiresAt: emailToken.expiresAt.toISOString(),
    });
  } catch (error) {
    console.error("Error validating invitation:", error);
    return res.status(500).json({ message: "Failed to validate invitation" });
  }
});

router.post("/accept", async (req: Request, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");

  try {
    const { token, password } = req.body as {
      token?: string;
      password?: string;
    };
    if (!token) {
      return res.status(400).json({ message: "Invitation token is required" });
    }
    if (!supabaseAdmin) {
      return res.status(500).json({
        message: "Supabase service role key not configured",
      });
    }

    const emailToken = await findActiveAuthEmailToken(
      token,
      AUTH_EMAIL_TOKEN_PURPOSE.INVITATION
    );
    if (!emailToken?.organizationMemberId) {
      return res.status(400).json({ message: "Invalid or expired invitation link" });
    }

    const { data: authData, error: authError } =
      await supabaseAdmin.auth.admin.getUserById(emailToken.authUserId);
    if (
      authError ||
      !authData.user ||
      normalizeEmail(authData.user.email || "") !== emailToken.email
    ) {
      return res.status(400).json({ message: "Invalid or expired invitation link" });
    }
    // A second outstanding invitation must never become a password-reset
    // primitive after another invitation has initialized the shared account.
    const requiresPassword =
      emailToken.requiresPassword && !authUserIsConfirmed(authData.user);

    if (requiresPassword) {
      if (!password) {
        return res.status(400).json({ message: "Password is required" });
      }
      if (password.length < 6) {
        return res.status(400).json({
          message: "Password must be at least 6 characters long",
        });
      }
    }

    const membership = await prisma.organizationMember.findUnique({
      where: { id: emailToken.organizationMemberId },
      include: { user: true, organization: true },
    });
    if (
      !membership ||
      membership.status !== "pending" ||
      normalizeEmail(membership.user.email) !== emailToken.email ||
      (membership.user.authUserId &&
        membership.user.authUserId !== emailToken.authUserId)
    ) {
      return res
        .status(400)
        .json({ message: "Invalid or expired invitation link" });
    }

    const claimedAt = await claimAuthEmailToken(emailToken.id);
    if (!claimedAt) {
      return res
        .status(400)
        .json({ message: "Invalid or expired invitation link" });
    }

    let authMutationAttempted = false;
    let invitationCompleted = false;
    try {
      if (requiresPassword) {
        // Once the external write is attempted, a thrown timeout has an
        // ambiguous outcome and the one-time token must remain consumed.
        authMutationAttempted = true;
        const { error: updateError } =
          await supabaseAdmin.auth.admin.updateUserById(emailToken.authUserId, {
            password,
            email_confirm: true,
          });
        if (updateError) {
          await releaseAuthEmailTokenClaim(emailToken.id, claimedAt);
          return res.status(400).json({
            message: "Password does not meet the account password requirements",
          });
        }
      }

      await prisma.$transaction(async (tx) => {
        const updated = await tx.organizationMember.updateMany({
          where: { id: membership.id, status: "pending" },
          data: { status: "verified" },
        });
        if (updated.count !== 1) {
          throw new Error("Invitation membership is no longer pending");
        }

        if (!membership.user.authUserId) {
          await tx.user.update({
            where: { id: membership.user.id },
            data: { authUserId: emailToken.authUserId },
          });
        }

        const verifiedCount = await tx.organizationMember.count({
          where: {
            organizationId: membership.organizationId,
            status: "verified",
          },
        });
        if (verifiedCount === 1) {
          await tx.organization.update({
            where: { id: membership.organizationId },
            data: {
              ownerEmail: membership.user.email,
              status: "active",
            },
          });
        }
      });
      invitationCompleted = true;

      const responseUser = {
        id: membership.user.id,
        email: membership.user.email,
        fullName: membership.user.fullName,
        role: membership.user.role || membership.role,
      };

      if (requiresPassword && password) {
        try {
          const { data: loginData, error: loginError } =
            await supabase.auth.signInWithPassword({
              email: membership.user.email,
              password,
            });
          if (!loginError && loginData.session) {
            return res.json({
              message: "Invitation accepted successfully",
              requiresLogin: false,
              user: responseUser,
              session: {
                access_token: loginData.session.access_token,
                refresh_token: loginData.session.refresh_token,
                expires_at: loginData.session.expires_at,
              },
            });
          }
        } catch (error) {
          console.error(
            "Invitation accepted but automatic sign-in failed:",
            error
          );
        }
      }

      return res.json({
        message: "Invitation accepted successfully. Please sign in to continue.",
        requiresLogin: true,
        user: responseUser,
      });
    } catch (error) {
      if (!authMutationAttempted && !invitationCompleted) {
        await releaseAuthEmailTokenClaim(emailToken.id, claimedAt).catch(
          () => undefined
        );
      }
      console.error("Error accepting invitation:", error);
      return res.status(500).json({ message: "Failed to accept invitation" });
    }
  } catch (error) {
    console.error("Error preparing invitation acceptance:", error);
    return res.status(500).json({ message: "Failed to accept invitation" });
  }
});

export { router as invitationRoutes };
