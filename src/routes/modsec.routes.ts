import { Router, Request, Response } from "express";
import {
  processAllModsecLandingRecords,
  processModsecLandingRecord,
} from "../services/modsecProcessor";
import { prisma } from "../lib/prisma";
import { modsecCronScheduler } from "../services/modsecCronScheduler";

const router = Router();

/**
 * @swagger
 * /api/modsec/process:
 *   post:
 *     summary: Process all unprocessed modsec_landing records
 *     tags: [ModSec]
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               organizationId:
 *                 type: string
 *                 description: Optional organization ID to associate logs with
 *               batchSize:
 *                 type: number
 *                 default: 100
 *                 description: Number of records to process per batch
 *     responses:
 *       200:
 *         description: Processing completed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 processed:
 *                   type: number
 *                 failed:
 *                   type: number
 *                 errors:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       error:
 *                         type: string
 */
router.post("/process", async (req: Request, res: Response) => {
  try {
    const { organizationId, batchSize = 100, async = false } = req.body;

    // If async mode, start processing in background and return immediately
    if (async) {
      // Start processing in background (don't await)
      processAllModsecLandingRecords(organizationId, batchSize)
        .then((result) => {
          console.log("✅ Background processing completed:", {
            processed: result.processed,
            failed: result.failed,
          });
        })
        .catch((error) => {
          console.error("❌ Background processing error:", error);
        });

      res.json({
        success: true,
        message: "Processing started in background",
        note: "Use /api/modsec/stats to check progress",
      });
      return;
    }

    // Synchronous mode (original behavior)
    const result = await processAllModsecLandingRecords(
      organizationId,
      batchSize
    );

    res.json({
      success: true,
      ...result,
    });
  } catch (error) {
    console.error("Error processing modsec_landing records:", error);
    res.status(500).json({
      success: false,
      error:
        error instanceof Error ? error.message : "Failed to process records",
    });
  }
});

/**
 * @swagger
 * /api/modsec/process/:id:
 *   post:
 *     summary: Process a single modsec_landing record by ID
 *     tags: [ModSec]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: The modsec_landing record ID
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               organizationId:
 *                 type: string
 *                 description: Optional organization ID to associate log with
 *     responses:
 *       200:
 *         description: Processing completed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 logId:
 *                   type: string
 *                 error:
 *                   type: string
 */
router.post("/process/:id", async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { organizationId } = req.body;

    const result = await processModsecLandingRecord(id, organizationId);

    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    console.error("Error processing modsec_landing record:", error);
    res.status(500).json({
      success: false,
      error:
        error instanceof Error ? error.message : "Failed to process record",
    });
  }
});

/**
 * @swagger
 * /api/modsec/landing:
 *   get:
 *     summary: Get modsec_landing records
 *     tags: [ModSec]
 *     parameters:
 *       - in: query
 *         name: processed
 *         schema:
 *           type: boolean
 *         description: Filter by processed status
 *       - in: query
 *         name: limit
 *         schema:
 *           type: number
 *           default: 100
 *         description: Maximum number of records to return
 *       - in: query
 *         name: offset
 *         schema:
 *           type: number
 *           default: 0
 *         description: Number of records to skip
 *     responses:
 *       200:
 *         description: List of modsec_landing records
 */
router.get("/landing", async (req: Request, res: Response) => {
  try {
    const { processed, limit = 100, offset = 0 } = req.query;

    const where: any = {};
    if (processed !== undefined) {
      where.processed = processed === "true";
    }

    const [records, total] = await Promise.all([
      prisma.modsecLanding.findMany({
        where,
        take: Number(limit),
        skip: Number(offset),
        orderBy: { time: "desc" },
      }),
      prisma.modsecLanding.count({ where }),
    ]);

    res.json({
      records,
      total,
      limit: Number(limit),
      offset: Number(offset),
    });
  } catch (error) {
    console.error("Error fetching modsec_landing records:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to fetch records",
    });
  }
});

/**
 * @swagger
 * /api/modsec/stats:
 *   get:
 *     summary: Get processing statistics
 *     tags: [ModSec]
 *     responses:
 *       200:
 *         description: Processing statistics
 */
router.get("/stats", async (req: Request, res: Response) => {
  try {
    const [total, processed, unprocessed] = await Promise.all([
      prisma.modsecLanding.count(),
      prisma.modsecLanding.count({ where: { processed: true } }),
      prisma.modsecLanding.count({ where: { processed: false } }),
    ]);

    const cronStatus = modsecCronScheduler.getStatus();

    res.json({
      total,
      processed,
      unprocessed,
      processingRate: total > 0 ? ((processed / total) * 100).toFixed(2) : "0",
      cron: {
        enabled: process.env.ENABLE_MODSEC_CRON !== "false",
        schedule: process.env.MODSEC_CRON_SCHEDULE || "* * * * *",
        running: cronStatus.running,
        isProcessing: cronStatus.isProcessing,
      },
    });
  } catch (error) {
    console.error("Error fetching stats:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to fetch stats",
    });
  }
});

export { router as modsecRoutes };
