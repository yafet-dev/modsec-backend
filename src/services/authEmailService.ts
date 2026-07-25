import { emailService } from "../lib/email";
import { normalizeEmail } from "../utils/normalizeEmail";

const AUTH_EMAIL_FRONTEND_PATH = {
  passwordReset: "/reset-password",
  invitation: "/accept-invitation",
} as const;

export interface AuthEmailDeliveryResult {
  success: boolean;
  error?: string;
}

export interface SendPasswordResetEmailInput {
  to: string;
  token: string;
}

export interface SendInvitationEmailInput {
  to: string;
  token: string;
  organizationName: string;
  role: string;
  requiresPassword: boolean;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function sanitizeSubjectValue(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

function getFrontendUrl(): URL {
  const configuredUrl = process.env.FRONTEND_URL?.trim();
  if (!configuredUrl) {
    throw new Error("FRONTEND_URL is required for authentication emails");
  }

  try {
    const url = new URL(
      configuredUrl.endsWith("/") ? configuredUrl : `${configuredUrl}/`
    );
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
      throw new Error("unsupported URL");
    }
    return url;
  } catch {
    throw new Error("FRONTEND_URL must be a valid HTTP(S) absolute URL");
  }
}

/** Auth mail is ready only when both SMTP and its public action URL are valid. */
export function isAuthEmailConfigured(): boolean {
  if (!emailService.isConfigured()) return false;

  try {
    getFrontendUrl();
    return true;
  } catch {
    return false;
  }
}

/**
 * Build a fragment-token link without ever writing it to application logs.
 * URL fragments stay in the browser and are not sent with the page request.
 */
export function buildAuthEmailLink(path: string, token: string): string {
  if (!token) {
    throw new Error("An auth email token is required");
  }

  const url = new URL(path.replace(/^\/+/, ""), getFrontendUrl());
  url.hash = new URLSearchParams({ token }).toString();
  return url.toString();
}

function emailLayout(options: {
  eyebrow: string;
  heading: string;
  bodyHtml: string;
  actionLabel: string;
  actionUrl: string;
  footer: string;
}): string {
  const actionUrl = escapeHtml(options.actionUrl);

  return `<!doctype html>
<html lang="en">
  <body style="margin:0;background:#f4f7fb;font-family:Arial,sans-serif;color:#172033">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f7fb;padding:32px 16px">
      <tr><td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;background:#ffffff;border-radius:12px;padding:36px;box-shadow:0 8px 30px rgba(23,32,51,.08)">
          <tr><td style="font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#2563eb">${escapeHtml(options.eyebrow)}</td></tr>
          <tr><td><h1 style="margin:12px 0 18px;font-size:28px;line-height:1.25;color:#172033">${escapeHtml(options.heading)}</h1></td></tr>
          <tr><td style="font-size:16px;line-height:1.65;color:#46536a">${options.bodyHtml}</td></tr>
          <tr><td style="padding:26px 0"><a href="${actionUrl}" style="display:inline-block;padding:13px 22px;border-radius:8px;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:700">${escapeHtml(options.actionLabel)}</a></td></tr>
          <tr><td style="font-size:13px;line-height:1.55;color:#758198">${escapeHtml(options.footer)}</td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>`;
}

export async function sendPasswordResetEmail(
  input: SendPasswordResetEmailInput
): Promise<AuthEmailDeliveryResult> {
  const to = normalizeEmail(input.to);
  const actionUrl = buildAuthEmailLink(
    AUTH_EMAIL_FRONTEND_PATH.passwordReset,
    input.token
  );
  const html = emailLayout({
    eyebrow: "Account security",
    heading: "Reset your password",
    bodyHtml:
      "<p style=\"margin:0\">We received a request to reset the password for your Zergaw account. Use the button below to choose a new password.</p>",
    actionLabel: "Reset password",
    actionUrl,
    footer:
      "If you did not request this change, you can safely ignore this email. This link can only be used once.",
  });

  return emailService.sendEmail({
    to,
    subject: "Reset your Zergaw password",
    html,
    text: `Reset your Zergaw password: ${actionUrl}\n\nIf you did not request this change, ignore this email. This link can only be used once.`,
  });
}

export async function sendInvitationEmail(
  input: SendInvitationEmailInput
): Promise<AuthEmailDeliveryResult> {
  const to = normalizeEmail(input.to);
  const organizationName = input.organizationName.trim();
  const role = input.role.trim();
  const actionUrl = buildAuthEmailLink(
    AUTH_EMAIL_FRONTEND_PATH.invitation,
    input.token
  );
  const passwordInstruction = input.requiresPassword
    ? " You will be asked to create a password when you accept."
    : " You can accept using your existing Zergaw account.";
  const bodyHtml = `<p style="margin:0">You have been invited to join <strong>${escapeHtml(
    organizationName
  )}</strong> as <strong>${escapeHtml(role)}</strong>.${escapeHtml(
    passwordInstruction
  )}</p>`;

  return emailService.sendEmail({
    to,
    subject: `Invitation to join ${sanitizeSubjectValue(organizationName)} on Zergaw`,
    html: emailLayout({
      eyebrow: "Organization invitation",
      heading: `Join ${organizationName}`,
      bodyHtml,
      actionLabel: "Accept invitation",
      actionUrl,
      footer:
        "If you were not expecting this invitation, you can safely ignore this email. This link can only be used once.",
    }),
    text: `You have been invited to join ${organizationName} as ${role}.${passwordInstruction}\n\nAccept the invitation: ${actionUrl}\n\nThis link can only be used once.`,
  });
}
