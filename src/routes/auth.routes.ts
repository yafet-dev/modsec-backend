import { Router, Request, Response } from "express";
import { supabase, supabaseAdmin } from "../lib/supabase";
import { prisma } from "../lib/prisma";
import {
  AUTH_EMAIL_TOKEN_PURPOSE,
  claimAuthEmailToken,
  createAuthEmailToken,
  deleteAuthEmailToken,
  findActiveAuthEmailToken,
  invalidateAllOtherAuthEmailTokens,
  invalidateOtherAuthEmailTokens,
  releaseAuthEmailTokenClaim,
} from "../services/authEmailTokenService";
import {
  isAuthEmailConfigured,
  sendPasswordResetEmail,
} from "../services/authEmailService";
import {
  findSupabaseAuthUserByEmail,
  normalizeEmail,
} from "../services/authUserService";

const router = Router();

const PASSWORD_RESET_WINDOW_MS = 15 * 60 * 1000;
const PASSWORD_RESET_MAX_REQUESTS = 5;
const PASSWORD_RESET_RESPONSE_FLOOR_MS = 350;
const passwordResetAttempts = new Map<
  string,
  { count: number; resetAt: number }
>();

function isPasswordResetRateLimited(key: string): boolean {
  const now = Date.now();
  const current = passwordResetAttempts.get(key);
  if (!current || current.resetAt <= now) {
    if (!current && passwordResetAttempts.size >= 10_000) {
      for (const [storedKey, attempt] of passwordResetAttempts) {
        if (attempt.resetAt <= now) passwordResetAttempts.delete(storedKey);
      }
      if (passwordResetAttempts.size >= 10_000) return true;
    }
    passwordResetAttempts.set(key, {
      count: 1,
      resetAt: now + PASSWORD_RESET_WINDOW_MS,
    });
    return false;
  }

  current.count += 1;
  return current.count > PASSWORD_RESET_MAX_REQUESTS;
}

async function waitForPasswordResetResponseFloor(startedAt: number): Promise<void> {
  const remaining = PASSWORD_RESET_RESPONSE_FLOOR_MS - (Date.now() - startedAt);
  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication endpoints using Supabase
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login with email and password
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User email address
 *               password:
 *                 type: string
 *                 format: password
 *                 description: User password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     email:
 *                       type: string
 *                 session:
 *                   type: object
 *                   properties:
 *                     access_token:
 *                       type: string
 *                     refresh_token:
 *                       type: string
 *       400:
 *         description: Invalid credentials
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
router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    // Authenticate with Supabase
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      return res.status(400).json({
        message: "Invalid credentials",
        error: error.message,
      });
    }

    if (!data.user || !data.session) {
      return res.status(400).json({
        message: "Authentication failed",
      });
    }

    // Get user from our database (user should already exist from invitation)
    const user = await prisma.user.findUnique({
      where: { email: data.user.email! },
      include: {
        memberships: {
          where: {
            status: "verified",
          },
          select: {
            role: true,
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found. Please accept an invitation first.",
      });
    }

    if (user.authUserId && user.authUserId !== data.user.id) {
      return res.status(409).json({
        message: "This account is linked to a different authentication identity",
      });
    }

    // Update last login timestamp
    await prisma.user.update({
      where: { id: user.id },
      data: {
        lastLogin: new Date(),
        ...(!user.authUserId && { authUserId: data.user.id }),
      },
    });

    // Determine user role: super_admin from user.role, or organization member role
    let userRole: string | null = user.role; // super_admin or null

    // If not super_admin, get role from organization membership
    if (!userRole && user.memberships.length > 0) {
      // Use the first verified membership role
      userRole = user.memberships[0].role;
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: userRole,
      },
      session: {
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at: data.session.expires_at,
      },
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({
      message: "Failed to login",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout user
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Logged out successfully
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post("/logout", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (token) {
      await supabase.auth.signOut();
    }

    res.json({
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Error during logout:", error);
    res.status(500).json({
      message: "Failed to logout",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Get current user
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Current user information
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
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
router.get("/me", async (req: Request, res: Response) => {
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

    // Get user from our database with memberships
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
      include: {
        memberships: {
          where: {
            status: "verified",
          },
          select: {
            role: true,
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (user.authUserId && user.authUserId !== supabaseUser.id) {
      return res.status(409).json({
        message: "This account is linked to a different authentication identity",
      });
    }
    if (!user.authUserId) {
      await prisma.user.update({
        where: { id: user.id },
        data: { authUserId: supabaseUser.id },
      });
    }

    // Determine user role: super_admin from user.role, or organization member role
    let userRole: string | null = user.role; // super_admin or null

    // If not super_admin, get role from organization membership
    if (!userRole && user.memberships.length > 0) {
      // Use the first verified membership role
      userRole = user.memberships[0].role;
    }

    res.json({
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: userRole,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    });
  } catch (error) {
    console.error("Error fetching current user:", error);
    res.status(500).json({
      message: "Failed to fetch user",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset email
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User email address
 *     responses:
 *       200:
 *         description: Password reset email sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Password reset email sent
 *       400:
 *         description: Invalid email or error sending email
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
router.post("/forgot-password", async (req: Request, res: Response) => {
  const startedAt = Date.now();
  const genericResponse = {
    message:
      "If an account with that email exists, a password reset link has been sent.",
  };
  const respondGenerically = async () => {
    await waitForPasswordResetResponseFloor(startedAt);
    return res.json(genericResponse);
  };
  const { email } = req.body as { email?: string };

  if (!email || typeof email !== "string") {
    return res.status(400).json({ message: "Email is required" });
  }

  const normalizedEmail = normalizeEmail(email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    return res.status(400).json({ message: "A valid email is required" });
  }
  if (!supabaseAdmin || !isAuthEmailConfigured()) {
    return res.status(503).json({
      message: "Password reset email delivery is not configured",
    });
  }

  // Account-scoped throttling works consistently behind reverse proxies and
  // avoids one shared proxy address blocking resets for every customer.
  if (isPasswordResetRateLimited(`account:${normalizedEmail}`)) {
    return respondGenerically();
  }

  let issuedTokenId: string | undefined;
  try {
    const localUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (!localUser) {
      return respondGenerically();
    }

    let authUser: Awaited<
      ReturnType<typeof findSupabaseAuthUserByEmail>
    >;
    if (localUser.authUserId) {
      const { data, error } = await supabaseAdmin.auth.admin.getUserById(
        localUser.authUserId
      );
      if (error || !data.user) {
        console.warn("Password reset ignored because the mapped Auth user is missing");
        return respondGenerically();
      }
      authUser = data.user;
    } else {
      // Legacy records are repaired once; unknown public addresses never cause
      // a paginated service-role scan of the Auth tenant.
      authUser = await findSupabaseAuthUserByEmail(normalizedEmail);
    }

    if (!authUser || normalizeEmail(authUser.email || "") !== normalizedEmail) {
      if (authUser) {
        console.warn("Password reset ignored because the account mapping is inconsistent");
      }
      return respondGenerically();
    }

    if (!localUser.authUserId) {
      await prisma.user.update({
        where: { id: localUser.id },
        data: { authUserId: authUser.id },
      });
    }

    const issued = await createAuthEmailToken({
      purpose: AUTH_EMAIL_TOKEN_PURPOSE.PASSWORD_RESET,
      email: normalizedEmail,
      authUserId: authUser.id,
    });
    issuedTokenId = issued.record.id;

    const delivery = await sendPasswordResetEmail({
      to: normalizedEmail,
      token: issued.token,
    });
    if (!delivery.success) {
      await deleteAuthEmailToken(issued.record.id).catch(() => undefined);
      console.error("Password reset SMTP delivery failed:", delivery.error);
      return respondGenerically();
    }

    try {
      await invalidateOtherAuthEmailTokens(issued.record);
    } catch (error) {
      console.error("Reset email sent but older tokens could not be invalidated:", error);
    }
    return respondGenerically();
  } catch (error) {
    if (issuedTokenId) {
      await deleteAuthEmailToken(issuedTokenId).catch(() => undefined);
    }
    console.error("Error processing password reset request:", error);
    return respondGenerically();
  }
});

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password using an application-issued one-time token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *               - token
 *             properties:
 *               password:
 *                 type: string
 *                 format: password
 *                 description: New password
 *               token:
 *                 type: string
 *                 description: One-time token from the backend SMTP email link
 *     responses:
 *       200:
 *         description: Password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Password reset successfully
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
router.post("/reset-password", async (req: Request, res: Response) => {
  const { password, token } = req.body as {
    password?: string;
    token?: string;
  };

  if (!password || !token) {
    return res.status(400).json({ message: "Password and token are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({
      message: "Password must be at least 6 characters long",
    });
  }
  if (!supabaseAdmin) {
    return res.status(500).json({
      message: "Supabase service role key not configured",
    });
  }

  try {
    const emailToken = await findActiveAuthEmailToken(
      token,
      AUTH_EMAIL_TOKEN_PURPOSE.PASSWORD_RESET
    );
    if (!emailToken) {
      return res.status(400).json({ message: "Invalid or expired reset link" });
    }

    const claimedAt = await claimAuthEmailToken(emailToken.id);
    if (!claimedAt) {
      return res.status(400).json({ message: "Invalid or expired reset link" });
    }

    let updateError: { message?: string } | null = null;
    try {
      const result = await supabaseAdmin.auth.admin.updateUserById(
        emailToken.authUserId,
        { password }
      );
      updateError = result.error;
    } catch (error) {
      // A timeout has an ambiguous outcome: Supabase may have committed the
      // password change before the response was lost. Keep the token consumed.
      console.error("Error resetting password:", error);
      return res.status(500).json({ message: "Failed to reset password" });
    }

    if (updateError) {
      await releaseAuthEmailTokenClaim(emailToken.id, claimedAt);
      return res.status(400).json({
        message: "Password does not meet the account password requirements",
      });
    }

    try {
      await invalidateAllOtherAuthEmailTokens(emailToken);
    } catch (error) {
      // The password has already changed and this token remains consumed.
      // Never release it after the external action succeeds.
      console.error("Failed to invalidate sibling password reset tokens:", error);
    }

    return res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Error preparing password reset:", error);
    return res.status(500).json({ message: "Failed to reset password" });
  }
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh access token using refresh token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refresh_token
 *             properties:
 *               refresh_token:
 *                 type: string
 *                 description: Refresh token from previous login
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 session:
 *                   type: object
 *                   properties:
 *                     access_token:
 *                       type: string
 *                     refresh_token:
 *                       type: string
 *                     expires_at:
 *                       type: number
 *       400:
 *         description: Invalid refresh token
 *       500:
 *         description: Server error
 */
router.post("/refresh", async (req: Request, res: Response) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({
        message: "Refresh token is required",
      });
    }

    // Create a Supabase client instance for this request
    const { createClient } = await import("@supabase/supabase-js");
    const supabaseClient = createClient(
      process.env.SUPABASE_URL!,
      process.env.SUPABASE_ANON_KEY!
    );

    // Refresh the session using the refresh token
    const { data, error } = await supabaseClient.auth.refreshSession({
      refresh_token,
    });

    if (error || !data.session) {
      return res.status(401).json({
        message: "Invalid or expired refresh token",
        error: error?.message || "Token refresh failed",
      });
    }

    res.json({
      session: {
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at: data.session.expires_at,
      },
    });
  } catch (error) {
    console.error("Error refreshing token:", error);
    res.status(500).json({
      message: "Failed to refresh token",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

export { router as authRoutes };
