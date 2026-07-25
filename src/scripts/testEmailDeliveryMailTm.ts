import "dotenv/config";

import { randomBytes } from "node:crypto";
import path from "node:path";
import { emailService } from "../lib/email";
import {
  sendInvitationEmail,
  sendPasswordResetEmail,
} from "../services/authEmailService";
import { generateAttackNotificationEmail } from "../services/notificationService";
import { buildSummaryReportHtml } from "../services/summaryReportHtml";

const MAIL_TM_BASE_URL = "https://api.mail.tm";
const DELIVERY_TIMEOUT_MS = 180_000;
const POLL_INTERVAL_MS = 3_000;

interface MailTmCollection<T> {
  "hydra:member": T[];
}

interface MailTmDomain {
  domain: string;
  isActive: boolean;
  isPrivate: boolean;
}

interface MailTmAccount {
  id: string;
  address: string;
}

interface MailTmToken {
  token: string;
}

interface MailTmAddress {
  address: string;
  name?: string;
}

interface MailTmMessageSummary {
  id: string;
  from: MailTmAddress;
  to: MailTmAddress[];
  subject: string;
  createdAt: string;
}

interface MailTmAttachment {
  filename?: string;
  contentType?: string;
  disposition?: string;
}

interface MailTmMessage extends MailTmMessageSummary {
  text?: string;
  html?: string[];
  attachments?: MailTmAttachment[];
}

interface DeliveryCase {
  flow: string;
  subject: string;
  bodyMarker: string;
  send: () => Promise<{ success: boolean; error?: string }>;
}

interface DeliveryProof {
  flow: string;
  messageId: string;
  subject: string;
  senderDomain: string;
  recipient: string;
  receivedAt: string;
  bodyMarkerVerified: boolean;
  attachmentCount: number;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function mailTmRequest<T>(
  pathname: string,
  init: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${MAIL_TM_BASE_URL}${pathname}`, {
    ...init,
    headers: {
      Accept: "application/ld+json, application/json",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(init.headers || {}),
    },
  });

  const responseText = await response.text();
  if (!response.ok) {
    throw new Error(
      `Mail.tm ${init.method || "GET"} ${pathname} returned ${response.status}: ${responseText.slice(0, 300)}`
    );
  }

  return JSON.parse(responseText) as T;
}

function senderDomain(address: string): string {
  return address.split("@").at(-1) || "unknown";
}

function messageBody(message: MailTmMessage): string {
  const html = Array.isArray(message.html) ? message.html.join("\n") : "";
  return `${message.text || ""}\n${html}`;
}

async function main(): Promise<void> {
  if (!emailService.isConfigured()) {
    throw new Error("SMTP is not configured");
  }

  const domainResponse = await mailTmRequest<MailTmCollection<MailTmDomain>>(
    "/domains?page=1"
  );
  const domain = domainResponse["hydra:member"].find(
    (candidate) => candidate.isActive && !candidate.isPrivate
  )?.domain;
  if (!domain) {
    throw new Error("Mail.tm did not return an active public domain");
  }

  const marker = `e2e-${Date.now()}-${randomBytes(3).toString("hex")}`;
  const address = `zergaw-${randomBytes(8).toString("hex")}@${domain}`;
  const password = `Zg!${randomBytes(24).toString("base64url")}`;
  const credentials = JSON.stringify({ address, password });

  const account = await mailTmRequest<MailTmAccount>("/accounts", {
    method: "POST",
    body: credentials,
  });
  const auth = await mailTmRequest<MailTmToken>("/token", {
    method: "POST",
    body: credentials,
  });
  const inboxHeaders = { Authorization: `Bearer ${auth.token}` };

  const resetToken = `reset-${marker}`;
  const invitationToken = `invite-${marker}`;
  const organizationName = `MailTm Proof ${marker}`;
  const alertHost = `${marker}.example.test`;
  const alertRule = `SQL Injection Proof ${marker}`;
  const alertSubject = `🚨 CRITICAL Security Alert: ${alertRule} on ${alertHost}`;
  const reportSubject = `Last 7 Days WAF report: ${alertHost} — ${organizationName}`;

  const alertHtml = generateAttackNotificationEmail(
    {
      action: "blocked",
      severity: "CRITICAL",
      rule: alertRule,
      ruleId: "942100",
      host: alertHost,
      method: "POST",
      requestUrl: "/mailtm-proof",
      clientIp: "203.0.113.10",
      clientPort: 44321,
      timestamp: new Date(),
      message: `Mail.tm delivery marker ${marker}`,
    },
    {
      id: `mailtm-${marker}`,
      name: organizationName,
      domains: [alertHost],
    }
  );

  const reportHtml = buildSummaryReportHtml({
    domain: alertHost,
    organizationName,
    logs: [],
    startDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1_000),
    endDate: new Date(),
    periodLabel: "Last 7 Days",
    logoCid: "zergaw-summary-logo",
  });

  const cases: DeliveryCase[] = [
    {
      flow: "password_reset",
      subject: "Reset your Zergaw password",
      bodyMarker: resetToken,
      send: () =>
        sendPasswordResetEmail({
          to: address,
          token: resetToken,
        }),
    },
    {
      flow: "organization_invitation_and_resend",
      subject: `Invitation to join ${organizationName} on Zergaw`,
      bodyMarker: invitationToken,
      send: () =>
        sendInvitationEmail({
          to: address,
          token: invitationToken,
          organizationName,
          role: "admin",
          requiresPassword: true,
        }),
    },
    {
      flow: "waf_security_alert_and_sample",
      subject: alertSubject,
      bodyMarker: marker,
      send: () =>
        emailService.sendEmail({
          to: address,
          subject: alertSubject,
          html: alertHtml,
        }),
    },
    {
      flow: "waf_summary_report",
      subject: reportSubject,
      bodyMarker: marker,
      send: () =>
        emailService.sendEmailWithInlineImage({
          to: address,
          subject: reportSubject,
          html: reportHtml,
          inlineImage: {
            path: path.join(process.cwd(), "assets", "Logo-blue.png"),
            cid: "zergaw-summary-logo",
            filename: "Logo-blue.png",
          },
        }),
    },
  ];

  for (const deliveryCase of cases) {
    const result = await deliveryCase.send();
    if (!result.success) {
      throw new Error(
        `${deliveryCase.flow} send failed: ${result.error || "unknown SMTP error"}`
      );
    }
  }

  const expectedSubjects = new Set(cases.map((deliveryCase) => deliveryCase.subject));
  const receivedBySubject = new Map<string, MailTmMessageSummary>();
  const deadline = Date.now() + DELIVERY_TIMEOUT_MS;

  while (Date.now() < deadline && receivedBySubject.size < expectedSubjects.size) {
    const inbox = await mailTmRequest<MailTmCollection<MailTmMessageSummary>>(
      "/messages?page=1",
      { headers: inboxHeaders }
    );

    for (const message of inbox["hydra:member"]) {
      if (expectedSubjects.has(message.subject)) {
        receivedBySubject.set(message.subject, message);
      }
    }

    if (receivedBySubject.size < expectedSubjects.size) {
      await delay(POLL_INTERVAL_MS);
    }
  }

  const missingSubjects = [...expectedSubjects].filter(
    (subject) => !receivedBySubject.has(subject)
  );
  if (missingSubjects.length > 0) {
    throw new Error(
      `Mail.tm delivery timed out; missing subjects: ${missingSubjects.join(" | ")}`
    );
  }

  const proofs: DeliveryProof[] = [];
  for (const deliveryCase of cases) {
    const summary = receivedBySubject.get(deliveryCase.subject);
    if (!summary) {
      throw new Error(`${deliveryCase.flow} disappeared from the Mail.tm inbox`);
    }

    const detail = await mailTmRequest<MailTmMessage>(
      `/messages/${encodeURIComponent(summary.id)}`,
      { headers: inboxHeaders }
    );
    const recipientVerified = detail.to.some(
      (recipient) => recipient.address.toLowerCase() === account.address.toLowerCase()
    );
    const bodyMarkerVerified = messageBody(detail).includes(deliveryCase.bodyMarker);

    if (!recipientVerified || !bodyMarkerVerified) {
      throw new Error(
        `${deliveryCase.flow} was received but failed content validation`
      );
    }

    proofs.push({
      flow: deliveryCase.flow,
      messageId: detail.id,
      subject: detail.subject,
      senderDomain: senderDomain(detail.from.address),
      recipient: account.address,
      receivedAt: detail.createdAt,
      bodyMarkerVerified,
      attachmentCount: detail.attachments?.length || 0,
    });
  }

  console.log(
    JSON.stringify(
      {
        status: "PASS",
        provider: "mail.tm",
        mailbox: account.address,
        expectedMessages: cases.length,
        receivedMessages: proofs.length,
        checkedAt: new Date().toISOString(),
        proofs,
      },
      null,
      2
    )
  );
}

main().catch((error: unknown) => {
  console.error(
    JSON.stringify(
      {
        status: "FAIL",
        error: error instanceof Error ? error.message : String(error),
        checkedAt: new Date().toISOString(),
      },
      null,
      2
    )
  );
  process.exitCode = 1;
});
