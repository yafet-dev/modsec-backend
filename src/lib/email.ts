import nodemailer from "nodemailer";
import addressparser from "nodemailer/lib/addressparser";

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  requireTls: boolean;
  user: string;
  pass: string;
  fromAddress: string;
  fromName: string;
}

export interface EmailOptions {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
}

export interface EmailResult {
  success: boolean;
  error?: string;
}

export interface SmtpSender {
  name: string;
  address: string;
}

const DEFAULT_SMTP_PORT = 587;
const DEFAULT_FROM_NAME = "Zergaw Cloud Firewall";

function envValue(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized || undefined;
}

export function parseSmtpPort(value: string | undefined): number {
  const rawPort = envValue(value) || String(DEFAULT_SMTP_PORT);

  if (!/^\d+$/.test(rawPort)) {
    throw new Error("SMTP_PORT must be an integer between 1 and 65535");
  }

  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error("SMTP_PORT must be an integer between 1 and 65535");
  }

  return port;
}

export function parseSmtpSecure(
  value: string | undefined,
  port: number
): boolean {
  const rawSecure = envValue(value)?.toLowerCase();

  if (rawSecure === undefined) {
    return port === 465;
  }

  if (rawSecure === "true") return true;
  if (rawSecure === "false") return false;

  throw new Error('SMTP_SECURE must be either "true" or "false"');
}

export function parseSmtpRequireTls(value: string | undefined): boolean {
  const rawRequireTls = envValue(value)?.toLowerCase();

  if (rawRequireTls === undefined) return true;
  if (rawRequireTls === "true") return true;
  if (rawRequireTls === "false") return false;

  throw new Error('SMTP_REQUIRE_TLS must be either "true" or "false"');
}

export function parseSmtpSender(
  value: string,
  configuredName?: string
): SmtpSender {
  const parsed = addressparser(value, { flatten: true });

  if (parsed.length !== 1 || !parsed[0].address) {
    throw new Error("SMTP_FROM must contain exactly one sender address");
  }

  return {
    address: parsed[0].address,
    name:
      envValue(configuredName) || envValue(parsed[0].name) || DEFAULT_FROM_NAME,
  };
}

/**
 * Read SMTP configuration exclusively from the supplied environment.
 * SMTP_FROM is preferred; EMAIL_FROM remains as a backwards-compatible
 * fallback, followed by the authenticated SMTP user.
 */
export function getSmtpConfig(
  env: NodeJS.ProcessEnv = process.env
): SmtpConfig | null {
  const host = envValue(env.SMTP_HOST);
  const user = envValue(env.SMTP_USER);
  const pass = envValue(env.SMTP_PASS);

  if (!host || !user || !pass) {
    return null;
  }

  const port = parseSmtpPort(env.SMTP_PORT);
  const sender = parseSmtpSender(
    envValue(env.SMTP_FROM) || envValue(env.EMAIL_FROM) || user,
    env.SMTP_FROM_NAME
  );

  return {
    host,
    port,
    secure: parseSmtpSecure(env.SMTP_SECURE, port),
    requireTls: parseSmtpRequireTls(env.SMTP_REQUIRE_TLS),
    user,
    pass,
    fromAddress: sender.address,
    fromName: sender.name,
  };
}

/**
 * Email service for backend-owned transactional messages and notifications.
 */
export class EmailService {
  private transporter: nodemailer.Transporter | null = null;
  private sender: { name: string; address: string } | null = null;

  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.initializeTransporter(env);
  }

  private initializeTransporter(env: NodeJS.ProcessEnv): void {
    let config: SmtpConfig | null;

    try {
      config = getSmtpConfig(env);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Invalid SMTP configuration";
      console.warn(`[email] ${message}. Email delivery is disabled.`);
      return;
    }

    if (!config) {
      console.warn(
        "[email] SMTP_HOST, SMTP_USER, and SMTP_PASS are required. Email delivery is disabled."
      );
      return;
    }

    this.sender = {
      name: config.fromName,
      address: config.fromAddress,
    };
    this.transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      requireTLS: !config.secure && config.requireTls,
      auth: {
        user: config.user,
        pass: config.pass,
      },
    });
  }

  /** Check whether all required SMTP settings were valid at startup. */
  isConfigured(): boolean {
    return this.transporter !== null && this.sender !== null;
  }

  /** Send a backend-owned transactional email or notification. */
  async sendEmail(options: EmailOptions): Promise<EmailResult> {
    if (!this.transporter || !this.sender) {
      return {
        success: false,
        error: "Email service not configured",
      };
    }

    try {
      const recipients = Array.isArray(options.to) ? options.to : [options.to];

      await this.transporter.sendMail({
        from: this.sender,
        to: recipients,
        subject: options.subject,
        html: options.html,
        text: options.text || this.htmlToText(options.html),
      });

      return { success: true };
    } catch (error) {
      console.error("Error sending email:", error);
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  /** Send HTML email with an optional inline image (CID). */
  async sendEmailWithInlineImage(
    options: EmailOptions & {
      inlineImage?: { path: string; cid: string; filename?: string };
    }
  ): Promise<EmailResult> {
    if (!this.transporter || !this.sender) {
      return {
        success: false,
        error: "Email service not configured",
      };
    }

    const fs = await import("fs/promises");

    try {
      const recipients = Array.isArray(options.to) ? options.to : [options.to];
      const attachments: Array<{
        filename: string;
        cid: string;
        content: Buffer;
      }> = [];

      if (options.inlineImage) {
        let content: Buffer;
        try {
          content = await fs.readFile(options.inlineImage.path);
        } catch {
          console.warn(
            `[email] Inline image not found: ${options.inlineImage.path}; sending without it`
          );
          return this.sendEmail(options);
        }

        attachments.push({
          filename: options.inlineImage.filename || "logo.png",
          content,
          cid: options.inlineImage.cid,
        });
      }

      await this.transporter.sendMail({
        from: this.sender,
        to: recipients,
        subject: options.subject,
        html: options.html,
        text: options.text || this.htmlToText(options.html),
        attachments: attachments.length > 0 ? attachments : undefined,
      });

      return { success: true };
    } catch (error) {
      console.error("Error sending email with inline image:", error);
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  private htmlToText(html: string): string {
    return html
      .replace(/<[^>]*>/g, "")
      .replace(/&nbsp;/g, " ")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .trim();
  }
}

export const emailService = new EmailService();
