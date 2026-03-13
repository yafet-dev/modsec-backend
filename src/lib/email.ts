import nodemailer from "nodemailer";

/**
 * Email service for sending notifications
 */
class EmailService {
  private transporter: nodemailer.Transporter | null = null;

  constructor() {
    this.initializeTransporter();
  }

  private initializeTransporter() {
    const smtpHost = process.env.SMTP_HOST;
    const smtpPort = parseInt(process.env.SMTP_PORT || "587", 10);
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const smtpSecure = process.env.SMTP_SECURE === "true" || smtpPort === 465;

    if (!smtpHost || !smtpUser || !smtpPass) {
      console.warn("⚠️  SMTP configuration missing. Email notifications will be disabled.");
      return;
    }

    this.transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    });
  }

  /**
   * Check if email service is configured
   */
  isConfigured(): boolean {
    return this.transporter !== null;
  }

  /**
   * Send email notification
   */
  async sendEmail(options: {
    to: string | string[];
    subject: string;
    html: string;
    text?: string;
  }): Promise<{ success: boolean; error?: string }> {
    if (!this.transporter) {
      return {
        success: false,
        error: "Email service not configured",
      };
    }

    const fromEmail = process.env.EMAIL_FROM || process.env.SMTP_USER || "noreply@zergaw.com";

    try {
      // Nodemailer accepts arrays directly, which is better for multiple recipients
      const recipients = Array.isArray(options.to) ? options.to : [options.to];
      
      await this.transporter.sendMail({
        from: `Zergaw Cloud Firewall <${fromEmail}>`,
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

  /**
   * Convert HTML to plain text (simple version)
   */
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
