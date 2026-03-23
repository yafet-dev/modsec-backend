// Load .env before any other imports so SUPABASE_* etc. are available when modules load
import "dotenv/config";

import express, { Express, Request, Response } from "express";
import cors from "cors";
import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import { userRoutes } from "./routes/user.routes";
import { authRoutes } from "./routes/auth.routes";
import { organizationRoutes } from "./routes/organization.routes";
import { invitationRoutes } from "./routes/invitation.routes";
import { organizationMembersRoutes } from "./routes/organization-members.routes";
import { modsecRoutes } from "./routes/modsec.routes";
import { logsRoutes } from "./routes/logs.routes";
import { domainWafRoutes } from "./routes/domain-waf.routes";
import { ipBanRoutes, publicIPBanRouter } from "./routes/ip-ban.routes";
import { geoAccessRoutes } from "./routes/geo-access.routes";
import { notificationSettingsRoutes } from "./routes/notification-settings.routes";
import { telegramWebhookRouter, telegramApiRouter } from "./routes/telegram.routes";
import { modsecCronScheduler } from "./services/modsecCronScheduler";
import { startSummaryReportCron, stopSummaryReportCron } from "./services/summaryReportCron";
import { summaryReportRoutes } from "./routes/summary-report.routes";

const app: Express = express();
const PORT = process.env.PORT || 3001;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

// Middleware
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "ModSecurity API",
      version: "1.0.0",
      description: "ModSecurity Backend API Documentation",
      contact: {
        name: "API Support",
      },
    },
    servers: [
      ...(process.env.API_PUBLIC_URL
        ? [
            {
              url: process.env.API_PUBLIC_URL.replace(/\/$/, ""),
              description: "Production / deployed API",
            },
          ]
        : []),
      {
        url: `http://localhost:${PORT}`,
        description: "Local development",
      },
    ],
    components: {
      schemas: {
        User: {
          type: "object",
          properties: {
            id: {
              type: "string",
              format: "uuid",
              description: "User unique identifier",
            },
            email: {
              type: "string",
              format: "email",
              description: "User email address",
            },
            fullName: {
              type: "string",
              nullable: true,
              description: "User full name",
            },
            role: {
              type: "string",
              nullable: true,
              enum: ["super_admin", null],
              description: "User role (super_admin or null)",
            },
            createdAt: {
              type: "string",
              format: "date-time",
              description: "User creation timestamp",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
              description: "User last update timestamp",
            },
          },
          required: ["id", "email", "createdAt", "updatedAt"],
        },
        Organization: {
          type: "object",
          properties: {
            id: {
              type: "string",
              format: "uuid",
              description: "Organization unique identifier",
            },
            name: {
              type: "string",
              description: "Organization name",
            },
            domains: {
              type: "array",
              items: {
                type: "string",
              },
              description: "Array of domain names",
            },
            ownerEmail: {
              type: "string",
              format: "email",
              nullable: true,
              description: "Email of the organization owner",
            },
            status: {
              type: "string",
              enum: ["active", "pending", "suspended", "disabled"],
              description: "Organization status",
            },
            createdAt: {
              type: "string",
              format: "date-time",
              description: "Organization creation timestamp",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
              description: "Organization last update timestamp",
            },
            members: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "string" },
                  userId: { type: "string" },
                  organizationId: { type: "string" },
                  role: { type: "string" },
                  status: { type: "string", enum: ["pending", "verified"] },
                  createdAt: { type: "string", format: "date-time" },
                  updatedAt: { type: "string", format: "date-time" },
                  user: {
                    type: "object",
                    properties: {
                      id: { type: "string" },
                      email: { type: "string" },
                      fullName: { type: "string", nullable: true },
                    },
                  },
                },
              },
            },
          },
          required: [
            "id",
            "name",
            "domains",
            "status",
            "createdAt",
            "updatedAt",
          ],
        },
        Error: {
          type: "object",
          properties: {
            message: {
              type: "string",
              description: "Error message",
            },
            error: {
              type: "string",
              description: "Error details",
            },
          },
        },
        GeoAccessControl: {
          type: "object",
          properties: {
            id: {
              type: "string",
              format: "uuid",
              description: "Geo access control unique identifier",
            },
            organizationId: {
              type: "string",
              format: "uuid",
              description: "Organization ID",
            },
            domain: {
              type: "string",
              description: "Domain name or '*' for all domains",
            },
            mode: {
              type: "string",
              enum: ["allow-all", "allow-only", "ban-specific"],
              description: "Filter mode: allow-all (no restrictions), allow-only (only selected countries), ban-specific (block selected countries)",
            },
            allowedCountries: {
              type: "array",
              items: {
                type: "string",
              },
              description: "ISO-3166-1 alpha-2 country codes for allow list",
            },
            deniedCountries: {
              type: "array",
              items: {
                type: "string",
              },
              description: "ISO-3166-1 alpha-2 country codes for deny list",
            },
            createdAt: {
              type: "string",
              format: "date-time",
              description: "Creation timestamp",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
              description: "Last update timestamp",
            },
          },
          required: [
            "id",
            "organizationId",
            "domain",
            "mode",
            "allowedCountries",
            "deniedCountries",
            "createdAt",
            "updatedAt",
          ],
        },
        NotificationSettings: {
          type: "object",
          properties: {
            id: {
              type: "string",
              format: "uuid",
              description: "Notification settings unique identifier",
            },
            organizationId: {
              type: "string",
              format: "uuid",
              description: "Organization ID",
            },
            notificationType: {
              type: "string",
              enum: ["email", "telegram"],
              description: "Notification channel type",
            },
            emailList: {
              type: "array",
              items: {
                type: "string",
              },
              description: "Array of email addresses (for email notifications)",
            },
            telegramChatId: {
              type: "string",
              nullable: true,
              description: "Telegram chat ID (for telegram notifications)",
            },
            domainFilter: {
              type: "string",
              enum: ["all", "specific"],
              description: "Domain filter type",
            },
            selectedDomains: {
              type: "array",
              items: {
                type: "string",
              },
              description: "Array of selected domains (if domainFilter is 'specific')",
            },
            severityFilter: {
              type: "string",
              enum: ["all", "critical", "high", "low"],
              description: "Severity level filter",
            },
            enabled: {
              type: "boolean",
              description: "Whether notifications are enabled",
            },
            createdAt: {
              type: "string",
              format: "date-time",
              description: "Creation timestamp",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
              description: "Last update timestamp",
            },
          },
          required: [
            "id",
            "organizationId",
            "notificationType",
            "emailList",
            "domainFilter",
            "selectedDomains",
            "severityFilter",
            "enabled",
            "createdAt",
            "updatedAt",
          ],
        },
      },
    },
  },
  apis: ["./src/routes/*.ts", "./src/server.ts"], // Path to the API files
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Swagger UI
app.use(
  "/docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    customCss: ".swagger-ui .topbar { display: none }",
    customSiteTitle: "ModSecurity API Documentation",
  })
);

// Health check endpoint
/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check endpoint
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Server is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: ok
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 */
app.get("/health", (req: Request, res: Response) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
  });
});

// Telegram webhook (must be before CORS/auth middleware in the chain; no auth required)
app.use("/telegram", telegramWebhookRouter);

// Public IP ban endpoint (no auth required)
app.use("/api/ip-bans", publicIPBanRouter);

// API Routes
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/organizations", organizationRoutes);
app.use("/api/organizations", summaryReportRoutes);
app.use("/api/organizations", domainWafRoutes);
app.use("/api/organizations", ipBanRoutes);
app.use("/api/organizations", geoAccessRoutes);
app.use("/api/organizations", notificationSettingsRoutes);
app.use("/api/telegram", telegramApiRouter);
app.use("/api/invitations", invitationRoutes);
app.use("/api/organization-members", organizationMembersRoutes);
app.use("/api/modsec", modsecRoutes);
app.use("/api/logs", logsRoutes);

// Root endpoint
app.get("/", (req: Request, res: Response) => {
  res.json({
    message: "ModSecurity API",
    version: "1.0.0",
    docs: "/docs",
  });
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    message: "Route not found",
    path: req.path,
  });
});

// Error handler
app.use((err: Error, req: Request, res: Response, next: Function) => {
  console.error(err.stack);
  res.status(500).json({
    message: "Internal server error",
    error: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(
    `📚 API Documentation available at http://localhost:${PORT}/docs`
  );

  // Start ModSec cron scheduler
  modsecCronScheduler.start();
  startSummaryReportCron();
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully...");
  modsecCronScheduler.stop();
  stopSummaryReportCron();
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully...");
  modsecCronScheduler.stop();
  stopSummaryReportCron();
  process.exit(0);
});

export default app;
