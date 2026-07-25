import "dotenv/config";

import { randomBytes } from "node:crypto";
import { prisma } from "../lib/prisma";
import { supabaseAdmin } from "../lib/supabase";
import { sendNotificationsForLogs } from "../services/notificationService";

const API_BASE_URL = process.env.EMAIL_ROUTE_TEST_API_URL || "http://localhost:3001/api";
const MAIL_TM_BASE_URL = "https://api.mail.tm";
const DELIVERY_TIMEOUT_MS = 180_000;
const POLL_INTERVAL_MS = 3_000;
const REQUEST_TIMEOUT_MS = 20_000;

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
  id?: string;
  token: string;
}

interface MailTmAddress {
  address: string;
}

interface MailTmMessageSummary {
  id: string;
  from: MailTmAddress;
  to: MailTmAddress[];
  subject: string;
  createdAt: string;
}

interface MailTmMessage extends MailTmMessageSummary {
  text?: string;
  html?: string[];
  attachments?: Array<{ filename?: string }>;
}

interface TestInbox {
  account: MailTmAccount;
  headers: { Authorization: string };
}

interface RouteProof {
  flow: string;
  route: string;
  routeStatus: number;
  messageId: string;
  subject: string;
  receivedAt: string;
  recipientVerified: boolean;
  bodyVerified: boolean;
  attachmentCount: number;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function assertSafeTestTarget(): void {
  if (process.env.NODE_ENV !== "development") {
    throw new Error("Route email tests are allowed only when NODE_ENV=development");
  }

  const apiUrl = new URL(API_BASE_URL);
  if (!["localhost", "127.0.0.1", "::1"].includes(apiUrl.hostname)) {
    throw new Error("Route email tests require a loopback API URL");
  }
}

async function mailTmRequest<T>(
  pathname: string,
  init: RequestInit = {}
): Promise<T> {
  const method = init.method || "GET";
  const attempts = method === "GET" || pathname === "/token" ? 4 : 1;
  let response: Response | undefined;
  let lastError: unknown;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      response = await fetch(`${MAIL_TM_BASE_URL}${pathname}`, {
        ...init,
        signal: init.signal || AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          Accept: "application/ld+json, application/json",
          ...(init.body ? { "Content-Type": "application/json" } : {}),
          ...(init.headers || {}),
        },
      });
      if (![429, 500, 502, 503, 504].includes(response.status) || attempt === attempts) {
        break;
      }
    } catch (error) {
      lastError = error;
      if (attempt === attempts) {
        throw new Error(
          `Mail.tm ${method} ${pathname} failed after ${attempts} attempt(s): ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
    await delay(attempt * 750);
  }

  if (!response) {
    throw new Error(
      `Mail.tm ${method} ${pathname} failed: ${
        lastError instanceof Error ? lastError.message : String(lastError)
      }`
    );
  }
  const text = await response.text();

  if (!response.ok) {
    throw new Error(
      `Mail.tm ${method} ${pathname} returned ${response.status}: ${text.slice(0, 250)}`
    );
  }

  return JSON.parse(text) as T;
}

async function deleteInbox(inbox: TestInbox): Promise<void> {
  let response: Response | undefined;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      response = await fetch(
        `${MAIL_TM_BASE_URL}/accounts/${encodeURIComponent(inbox.account.id)}`,
        {
          method: "DELETE",
          headers: inbox.headers,
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        }
      );
      if (response.ok || response.status === 404 || attempt === 3) break;
    } catch (error) {
      if (attempt === 3) {
        throw new Error(
          `Mail.tm account cleanup failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
    await delay(attempt * 750);
  }

  if (!response) throw new Error("Mail.tm account cleanup produced no response");
  if (!response.ok && response.status !== 404) {
    throw new Error(`Mail.tm account cleanup returned ${response.status}`);
  }
}

async function createInbox(domain: string): Promise<TestInbox> {
  const address = `zergaw-route-${randomBytes(8).toString("hex")}@${domain}`;
  const password = `Zg!${randomBytes(24).toString("base64url")}`;
  const body = JSON.stringify({ address, password });
  let account: MailTmAccount;
  let auth: MailTmToken | undefined;

  try {
    account = await mailTmRequest<MailTmAccount>("/accounts", {
      method: "POST",
      body,
    });
  } catch (accountError) {
    // If the connection dropped after Mail.tm committed the account, obtaining
    // its token recovers the otherwise orphaned test inbox safely.
    try {
      auth = await mailTmRequest<MailTmToken>("/token", {
        method: "POST",
        body,
      });
    } catch {
      throw accountError;
    }
    if (!auth.id) throw accountError;
    account = { id: auth.id, address };
  }

  auth ||= await mailTmRequest<MailTmToken>("/token", {
    method: "POST",
    body,
  });

  return {
    account,
    headers: { Authorization: `Bearer ${auth.token}` },
  };
}

async function apiRequest<T>(
  pathname: string,
  options: {
    method?: string;
    token?: string;
    body?: unknown;
    expectedStatus?: number;
  } = {}
): Promise<{ status: number; body: T }> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${pathname}`, {
      method: options.method || "GET",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: {
        Accept: "application/json",
        ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
        ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
      },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });
  } catch (error) {
    throw new Error(
      `${options.method || "GET"} ${pathname} failed: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
  const text = await response.text();
  let body: T;
  try {
    body = JSON.parse(text) as T;
  } catch {
    throw new Error(
      `${options.method || "GET"} ${pathname} returned non-JSON ${response.status}: ${text.slice(0, 250)}`
    );
  }

  const expectedStatus = options.expectedStatus ?? 200;
  if (response.status !== expectedStatus) {
    throw new Error(
      `${options.method || "GET"} ${pathname} returned ${response.status}, expected ${expectedStatus}: ${text.slice(0, 300)}`
    );
  }

  return { status: response.status, body };
}

async function inboxMessages(inbox: TestInbox): Promise<MailTmMessageSummary[]> {
  const response = await mailTmRequest<MailTmCollection<MailTmMessageSummary>>(
    "/messages?page=1",
    { headers: inbox.headers }
  );
  return response["hydra:member"];
}

async function waitForMessages(
  inbox: TestInbox,
  predicate: (message: MailTmMessageSummary) => boolean,
  count: number
): Promise<MailTmMessageSummary[]> {
  const deadline = Date.now() + DELIVERY_TIMEOUT_MS;

  while (Date.now() < deadline) {
    const matches = (await inboxMessages(inbox))
      .filter(predicate)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    if (matches.length >= count) return matches;
    await delay(POLL_INTERVAL_MS);
  }

  throw new Error(`Mail.tm timed out waiting for ${count} matching message(s)`);
}

async function messageDetail(
  inbox: TestInbox,
  messageId: string
): Promise<MailTmMessage> {
  return mailTmRequest<MailTmMessage>(
    `/messages/${encodeURIComponent(messageId)}`,
    { headers: inbox.headers }
  );
}

function bodyText(message: MailTmMessage): string {
  return `${message.text || ""}\n${Array.isArray(message.html) ? message.html.join("\n") : ""}`;
}

function tokenFromMessage(message: MailTmMessage): string {
  const match = bodyText(message).match(/#token=([A-Za-z0-9_%.-]+)/);
  if (!match) throw new Error(`No action token found in message ${message.id}`);
  return decodeURIComponent(match[1]);
}

function proofFor(
  flow: string,
  route: string,
  routeStatus: number,
  inbox: TestInbox,
  message: MailTmMessage,
  bodyMarker: string
): RouteProof {
  return {
    flow,
    route,
    routeStatus,
    messageId: message.id,
    subject: message.subject,
    receivedAt: message.createdAt,
    recipientVerified: message.to.some(
      (recipient) =>
        recipient.address.toLowerCase() === inbox.account.address.toLowerCase()
    ),
    bodyVerified: bodyText(message).includes(bodyMarker),
    attachmentCount: message.attachments?.length || 0,
  };
}

async function main(): Promise<void> {
  assertSafeTestTarget();
  if (!supabaseAdmin) {
    throw new Error("SUPABASE_SERVICE_ROLE_KEY is required");
  }
  const admin = supabaseAdmin;
  const marker = `route-e2e-${Date.now()}-${randomBytes(3).toString("hex")}`;
  const organizationName = `MailTm Route Proof ${marker}`;
  const testDomain = `${marker}.example.test`;
  const creatorPassword = `Creator!${randomBytes(18).toString("base64url")}`;
  const memberPassword = `Member!${randomBytes(18).toString("base64url")}`;
  const resetPassword = `Reset!${randomBytes(18).toString("base64url")}`;
  const createdAuthUserIds: string[] = [];
  let creatorInbox: TestInbox | undefined;
  let memberInbox: TestInbox | undefined;
  let resendInbox: TestInbox | undefined;
  let organizationId: string | undefined;
  const proofs: RouteProof[] = [];
  let output: Record<string, unknown> | undefined;
  let failure: unknown;
  const cleanupErrors: string[] = [];

  try {
    const domainResponse = await mailTmRequest<MailTmCollection<MailTmDomain>>(
      "/domains?page=1"
    );
    const mailDomain = domainResponse["hydra:member"].find(
      (candidate) => candidate.isActive && !candidate.isPrivate
    )?.domain;
    if (!mailDomain) throw new Error("Mail.tm has no active public domain");

    creatorInbox = await createInbox(mailDomain);
    memberInbox = await createInbox(mailDomain);
    resendInbox = await createInbox(mailDomain);
    const creator = creatorInbox;
    const member = memberInbox;
    const resendTarget = resendInbox;

    const creatorAuth = await admin.auth.admin.createUser({
      email: creator.account.address,
      password: creatorPassword,
      email_confirm: true,
      user_metadata: { test_marker: marker },
    });
    if (creatorAuth.error || !creatorAuth.data.user) {
      throw new Error(
        `Could not create temporary creator: ${creatorAuth.error?.message || "no user"}`
      );
    }
    createdAuthUserIds.push(creatorAuth.data.user.id);

    await prisma.user.create({
      data: {
        id: creatorAuth.data.user.id,
        authUserId: creatorAuth.data.user.id,
        email: creator.account.address,
        fullName: "Mail.tm Route Test",
      },
    });

    const creatorLogin = await apiRequest<{
      session: { access_token: string };
    }>("/auth/login", {
      method: "POST",
      body: {
        email: creator.account.address,
        password: creatorPassword,
      },
    });
    const creatorToken = creatorLogin.body.session.access_token;

    const createOrganization = await apiRequest<{
      id: string;
      members: Array<{ id: string }>;
    }>("/organizations", {
      method: "POST",
      token: creatorToken,
      expectedStatus: 201,
      body: {
        name: organizationName,
        domains: [testDomain],
        adminEmail: member.account.address,
      },
    });
    organizationId = createOrganization.body.id;
    if (!createOrganization.body.members[0]?.id) {
      throw new Error("Organization response omitted membership ID");
    }

    const provisionedMember = await prisma.user.findUnique({
      where: { email: member.account.address },
      select: { authUserId: true },
    });
    if (!provisionedMember?.authUserId) {
      throw new Error("Invitation did not provision a mapped Auth user");
    }
    createdAuthUserIds.push(provisionedMember.authUserId);

    const invitationSubject = `Invitation to join ${organizationName} on Zergaw`;
    const firstInviteSummary = (
      await waitForMessages(
        member,
        (message) => message.subject === invitationSubject,
        1
      )
    )[0];
    const firstInvite = await messageDetail(member, firstInviteSummary.id);
    const firstInviteToken = tokenFromMessage(firstInvite);
    proofs.push(
      proofFor(
        "organization_invitation",
        "POST /api/organizations",
        createOrganization.status,
        member,
        firstInvite,
        organizationName
      )
    );

    const validatedInvite = await apiRequest<{ requiresPassword: boolean }>(
      "/invitations/validate",
      {
        method: "POST",
        body: { token: firstInviteToken },
      }
    );
    if (!validatedInvite.body.requiresPassword) {
      throw new Error("New Mail.tm invite unexpectedly did not require a password");
    }

    const acceptedInvite = await apiRequest<{
      session?: { access_token: string };
    }>("/invitations/accept", {
      method: "POST",
      body: { token: firstInviteToken, password: memberPassword },
    });
    let memberToken = acceptedInvite.body.session?.access_token;
    if (!memberToken) {
      const memberLogin = await apiRequest<{
        session: { access_token: string };
      }>("/auth/login", {
        method: "POST",
        body: { email: member.account.address, password: memberPassword },
      });
      memberToken = memberLogin.body.session.access_token;
    }

    const activatedOrganization = await prisma.organization.findUnique({
      where: { id: organizationId },
      select: { status: true, ownerEmail: true },
    });
    if (
      activatedOrganization?.status !== "active" ||
      activatedOrganization.ownerEmail !== member.account.address
    ) {
      throw new Error("Accepting the first admin invitation did not activate the organization");
    }

    const memberInvite = await apiRequest<{
      member: { id: string };
    }>("/organization-members/invite", {
      method: "POST",
      token: memberToken,
      expectedStatus: 201,
      body: { email: resendTarget.account.address, role: "viewer" },
    });
    const resendMemberId = memberInvite.body.member.id;
    const provisionedResendUser = await prisma.user.findUnique({
      where: { email: resendTarget.account.address },
      select: { authUserId: true },
    });
    if (!provisionedResendUser?.authUserId) {
      throw new Error("Member invitation did not provision a mapped Auth user");
    }
    createdAuthUserIds.push(provisionedResendUser.authUserId);

    const memberInviteSummary = (
      await waitForMessages(
        resendTarget,
        (message) => message.subject === invitationSubject,
        1
      )
    )[0];
    const memberInviteMessage = await messageDetail(
      resendTarget,
      memberInviteSummary.id
    );
    const memberInviteToken = tokenFromMessage(memberInviteMessage);
    proofs.push(
      proofFor(
        "organization_member_invitation",
        "POST /api/organization-members/invite",
        memberInvite.status,
        resendTarget,
        memberInviteMessage,
        organizationName
      )
    );

    const resend = await apiRequest<{ message: string }>(
      `/organization-members/${resendMemberId}/resend-invitation`,
      {
        method: "POST",
        token: memberToken,
      }
    );
    const invitationSummaries = await waitForMessages(
      resendTarget,
      (message) => message.subject === invitationSubject,
      2
    );
    const resentInvite = await messageDetail(
      resendTarget,
      invitationSummaries[invitationSummaries.length - 1].id
    );
    const resentInviteToken = tokenFromMessage(resentInvite);
    proofs.push(
      proofFor(
        "invitation_resend",
        "POST /api/organization-members/:memberId/resend-invitation",
        resend.status,
        resendTarget,
        resentInvite,
        organizationName
      )
    );

    await apiRequest<{ message: string }>("/invitations/validate", {
      method: "POST",
      expectedStatus: 400,
      body: { token: memberInviteToken },
    });
    await apiRequest<{ requiresPassword: boolean }>("/invitations/validate", {
      method: "POST",
      body: { token: resentInviteToken },
    });

    const forgotPassword = await apiRequest<{ message: string }>(
      "/auth/forgot-password",
      {
        method: "POST",
        body: { email: member.account.address },
      }
    );
    const resetSummary = (
      await waitForMessages(
        member,
        (message) => message.subject === "Reset your Zergaw password",
        1
      )
    )[0];
    const resetMessage = await messageDetail(member, resetSummary.id);
    const resetToken = tokenFromMessage(resetMessage);
    proofs.push(
      proofFor(
        "password_reset_email",
        "POST /api/auth/forgot-password",
        forgotPassword.status,
        member,
        resetMessage,
        resetToken
      )
    );

    await apiRequest<{ message: string }>("/auth/reset-password", {
      method: "POST",
      body: { token: resetToken, password: resetPassword },
    });
    const resetLogin = await apiRequest<{
      session: { access_token: string };
    }>("/auth/login", {
      method: "POST",
      body: { email: member.account.address, password: resetPassword },
    });
    memberToken = resetLogin.body.session.access_token;

    const sampleAlert = await apiRequest<{ message: string }>(
      `/organizations/${organizationId}/notification-settings/send-sample`,
      {
        method: "POST",
        token: memberToken,
        body: {
          notificationType: "email",
          emailList: [member.account.address],
        },
      }
    );
    const sampleSummary = (
      await waitForMessages(
        member,
        (message) =>
          message.subject.startsWith("[SAMPLE]") && message.subject.includes(testDomain),
        1
      )
    )[0];
    const sampleMessage = await messageDetail(member, sampleSummary.id);
    proofs.push(
      proofFor(
        "sample_waf_alert",
        "POST /api/organizations/:id/notification-settings/send-sample",
        sampleAlert.status,
        member,
        sampleMessage,
        testDomain
      )
    );

    await prisma.notificationSettings.create({
      data: {
        organizationId,
        notificationType: "email",
        emailList: [member.account.address],
        domainFilter: "all",
        selectedDomains: [testDomain],
        severityFilter: "all",
        enabled: true,
      },
    });
    const liveRule = `Route SQL Injection ${marker}`;
    const liveLog = await prisma.log.create({
      data: {
        organizationId,
        action: "blocked",
        severity: "CRITICAL",
        timestamp: new Date(),
        clientIp: "203.0.113.25",
        clientPort: 49152,
        host: testDomain,
        method: "POST",
        requestUrl: "/route-email-proof",
        rule: liveRule,
        ruleId: "942100",
        message: `Route email proof ${marker}`,
      },
    });
    const liveResult = await sendNotificationsForLogs([liveLog.id]);
    if (liveResult.sent !== 1 || liveResult.failed !== 0) {
      throw new Error(`Real WAF alert service returned ${JSON.stringify(liveResult)}`);
    }
    const liveSummary = (
      await waitForMessages(
        member,
        (message) => message.subject.includes(liveRule),
        1
      )
    )[0];
    const liveMessage = await messageDetail(member, liveSummary.id);
    proofs.push(
      proofFor(
        "real_time_waf_alert",
        "sendNotificationsForLogs",
        200,
        member,
        liveMessage,
        marker
      )
    );

    const summaryReport = await apiRequest<{ sent: number; errors?: string[] }>(
      `/organizations/${organizationId}/summary-report/send-now`,
      {
        method: "POST",
        token: memberToken,
        body: { emails: [member.account.address] },
      }
    );
    if (summaryReport.body.sent !== 1 || summaryReport.body.errors?.length) {
      throw new Error(`Summary route returned ${JSON.stringify(summaryReport.body)}`);
    }
    const reportSummary = (
      await waitForMessages(
        member,
        (message) =>
          message.subject.includes("WAF report") && message.subject.includes(testDomain),
        1
      )
    )[0];
    const reportMessage = await messageDetail(member, reportSummary.id);
    proofs.push(
      proofFor(
        "manual_waf_summary_report",
        "POST /api/organizations/:id/summary-report/send-now",
        summaryReport.status,
        member,
        reportMessage,
        testDomain
      )
    );

    const invalidProof = proofs.find(
      (proof) =>
        !proof.recipientVerified || !proof.bodyVerified || proof.routeStatus >= 300
    );
    if (invalidProof) {
      throw new Error(`Proof validation failed for ${invalidProof.flow}`);
    }
    const reportProof = proofs.find(
      (proof) => proof.flow === "manual_waf_summary_report"
    );
    if (!reportProof || reportProof.attachmentCount < 1) {
      throw new Error("Summary report was received without its inline logo attachment");
    }

    output = {
      status: "PASS",
      provider: "mail.tm",
      mailbox: member.account.address,
      checkedAt: new Date().toISOString(),
      routeFlowsPassed: proofs.length,
      invitationAccepted: true,
      organizationActivated: true,
      passwordResetCompleted: true,
      proofs,
    };
  } catch (error) {
    failure = error;
  } finally {
    const inboxes = [creatorInbox, memberInbox, resendInbox].filter(
      (inbox): inbox is TestInbox => Boolean(inbox)
    );
    const testEmails = inboxes.map((inbox) => inbox.account.address.toLowerCase());

    try {
      const testOrganizations = await prisma.organization.findMany({
        where: {
          OR: [
            ...(organizationId ? [{ id: organizationId }] : []),
            { name: organizationName },
          ],
        },
        select: { id: true, name: true, domains: true },
      });

      for (const organization of testOrganizations) {
        const markerMatches =
          organization.name === organizationName &&
          organization.domains.length === 1 &&
          organization.domains[0] === testDomain;
        if (!markerMatches) {
          cleanupErrors.push(
            `Refused to delete organization ${organization.id}: marker mismatch`
          );
          continue;
        }
        await prisma.iPBanToken.deleteMany({
          where: { organizationId: organization.id },
        });
        await prisma.organization.delete({ where: { id: organization.id } });
      }
    } catch (error) {
      cleanupErrors.push(
        `Database organization cleanup failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }

    if (testEmails.length > 0) {
      try {
        await prisma.authEmailToken.deleteMany({
          where: { email: { in: testEmails } },
        });
        await prisma.user.deleteMany({
          where: { email: { in: testEmails } },
        });
      } catch (error) {
        cleanupErrors.push(
          `Database identity cleanup failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }

    const authUserIdsToDelete = new Set(createdAuthUserIds);
    for (let page = 1; ; page += 1) {
      const listed = await admin.auth.admin.listUsers({ page, perPage: 1000 });
      if (listed.error) {
        cleanupErrors.push("Supabase Auth cleanup discovery failed");
        break;
      }
      for (const user of listed.data.users) {
        if (
          typeof user.email === "string" &&
          testEmails.includes(user.email.toLowerCase()) &&
          (user.user_metadata?.test_marker === marker ||
            user.user_metadata?.organization_name === organizationName)
        ) {
          authUserIdsToDelete.add(user.id);
        }
      }
      if (listed.data.users.length < 1000) break;
    }

    for (const userId of [...authUserIdsToDelete].reverse()) {
      const lookup = await admin.auth.admin.getUserById(userId);
      if (lookup.error) {
        if ((lookup.error as { status?: number }).status !== 404) {
          cleanupErrors.push(`Supabase lookup cleanup failed for ${userId}`);
        }
        continue;
      }

      const authUser = lookup.data.user;
      const emailMatches =
        typeof authUser?.email === "string" &&
        testEmails.includes(authUser.email.toLowerCase());
      const metadataMatches =
        authUser?.user_metadata?.test_marker === marker ||
        authUser?.user_metadata?.organization_name === organizationName;
      if (!emailMatches || !metadataMatches) {
        cleanupErrors.push(`Refused to delete Auth user ${userId}: marker mismatch`);
        continue;
      }

      const deleted = await admin.auth.admin.deleteUser(userId);
      if (deleted.error) {
        cleanupErrors.push(`Supabase Auth cleanup failed for ${userId}`);
      }
    }

    for (const inbox of inboxes.reverse()) {
      try {
        await deleteInbox(inbox);
      } catch (error) {
        cleanupErrors.push(
          `Mail.tm cleanup failed for ${inbox.account.id}: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }

    try {
      await prisma.$disconnect();
    } catch (error) {
      cleanupErrors.push(
        `Prisma disconnect failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  if (cleanupErrors.length > 0) {
    const originalFailure =
      failure instanceof Error ? ` Original failure: ${failure.message}` : "";
    throw new Error(`Test cleanup was incomplete: ${cleanupErrors.join(" | ")}.${originalFailure}`);
  }
  if (failure) throw failure;
  if (!output) throw new Error("Route test completed without a result");

  console.log(JSON.stringify(output, null, 2));
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
