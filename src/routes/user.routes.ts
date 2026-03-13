import { Router, Request, Response } from 'express';
import { prisma } from '../lib/prisma';
import { supabase } from '../lib/supabase';
import crypto from 'crypto';

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Users
 *   description: User management endpoints
 */

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users with organization memberships (super_admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users with their organization memberships
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   email:
 *                     type: string
 *                   fullName:
 *                     type: string
 *                     nullable: true
 *                   disabled:
 *                     type: boolean
 *                   lastLogin:
 *                     type: string
 *                     nullable: true
 *                   role:
 *                     type: string
 *                     nullable: true
 *                   memberships:
 *                     type: array
 *                     items:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: string
 *                         organizationId:
 *                           type: string
 *                         role:
 *                           type: string
 *                         status:
 *                           type: string
 *                         organization:
 *                           type: object
 *                           properties:
 *                             id:
 *                               type: string
 *                             name:
 *                               type: string
 *                             domains:
 *                               type: array
 *                               items:
 *                                 type: string
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden (not super_admin)
 *       500:
 *         description: Server error
 */
router.get('/', async (req: Request, res: Response) => {
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

    // Get user from our database to check if super_admin
    const currentUser = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
    });

    if (!currentUser) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Only super_admin can access all users
    if (currentUser.role !== "super_admin") {
      return res.status(403).json({
        message: "Forbidden: Only super_admin can access all users",
      });
    }

    // Get all users with their organization memberships
    const users = await prisma.user.findMany({
      include: {
        memberships: {
          include: {
            organization: {
              select: {
                id: true,
                name: true,
                domains: true,
              },
            },
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    // Format response
    const formattedUsers = users.map((user) => ({
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      disabled: user.disabled,
      lastLogin: user.lastLogin?.toISOString() || null,
      role: user.role,
      memberships: user.memberships.map((membership) => ({
        id: membership.id,
        organizationId: membership.organizationId,
        role: membership.role,
        status: membership.status,
        organization: membership.organization,
      })),
    }));

    res.json(formattedUsers);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      message: 'Failed to fetch users',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags: [Users]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: User ID
 *     responses:
 *       200:
 *         description: User details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       404:
 *         description: User not found
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
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const user = await prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      message: 'Failed to fetch user',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * @swagger
 * /api/users:
 *   post:
 *     summary: Create a new user
 *     tags: [Users]
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
 *               fullName:
 *                 type: string
 *                 nullable: true
 *                 description: User full name
 *               role:
 *                 type: string
 *                 nullable: true
 *                 enum: [super_admin, null]
 *                 description: User role (super_admin or null)
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       400:
 *         description: Invalid input
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
router.post('/', async (req: Request, res: Response) => {
  try {
    const { email, fullName, role } = req.body;

    if (!email) {
      return res.status(400).json({
        message: 'Email is required',
      });
    }

    // Validate role if provided
    if (role && role !== 'super_admin') {
      return res.status(400).json({
        message: 'Role must be "super_admin" or null',
      });
    }

    const user = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email,
        fullName: fullName || null,
        role: role === 'super_admin' ? 'super_admin' : null,
      },
    });

    res.status(201).json(user);
  } catch (error: any) {
    console.error('Error creating user:', error);
    
    if (error.code === 'P2002') {
      return res.status(409).json({
        message: 'User with this email already exists',
      });
    }

    res.status(500).json({
      message: 'Failed to create user',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * @swagger
 * /api/users/{id}:
 *   put:
 *     summary: Update user by ID
 *     tags: [Users]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User email address
 *               fullName:
 *                 type: string
 *                 nullable: true
 *                 description: User full name
 *               role:
 *                 type: string
 *                 nullable: true
 *                 enum: [super_admin, null]
 *                 description: User role (super_admin or null)
 *     responses:
 *       200:
 *         description: User updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       404:
 *         description: User not found
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
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { email, fullName, role } = req.body;

    // Validate role if provided
    if (role !== undefined && role !== null && role !== 'super_admin') {
      return res.status(400).json({
        message: 'Role must be "super_admin" or null',
      });
    }

    const user = await prisma.user.update({
      where: { id },
      data: {
        ...(email && { email }),
        ...(fullName !== undefined && { fullName }),
        ...(role !== undefined && { role: role === 'super_admin' ? 'super_admin' : null }),
      },
    });

    res.json(user);
  } catch (error: any) {
    console.error('Error updating user:', error);
    
    if (error.code === 'P2025') {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    if (error.code === 'P2002') {
      return res.status(409).json({
        message: 'User with this email already exists',
      });
    }

    res.status(500).json({
      message: 'Failed to update user',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Delete user by ID
 *     tags: [Users]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: User ID
 *     responses:
 *       200:
 *         description: User deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User deleted successfully
 *       404:
 *         description: User not found
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
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    await prisma.user.delete({
      where: { id },
    });

    res.json({
      message: 'User deleted successfully',
    });
  } catch (error: any) {
    console.error('Error deleting user:', error);
    
    if (error.code === 'P2025') {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    res.status(500).json({
      message: 'Failed to delete user',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

export { router as userRoutes };

