import { createHash, randomBytes } from "crypto";
import type { AuthEmailToken } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { normalizeEmail } from "../utils/normalizeEmail";

export const AUTH_EMAIL_TOKEN_PURPOSE = {
  PASSWORD_RESET: "password_reset",
  INVITATION: "invitation",
} as const;

export type AuthEmailTokenPurpose =
  (typeof AUTH_EMAIL_TOKEN_PURPOSE)[keyof typeof AUTH_EMAIL_TOKEN_PURPOSE];

const DEFAULT_PASSWORD_RESET_TTL_MINUTES = 60;
const DEFAULT_INVITATION_TTL_HOURS = 72;

export interface CreateAuthEmailTokenInput {
  purpose: AuthEmailTokenPurpose;
  email: string;
  authUserId: string;
  organizationMemberId?: string | null;
  requiresPassword?: boolean;
}

export interface CreatedAuthEmailToken {
  /** The raw token. Send it once and never persist or log it. */
  token: string;
  record: AuthEmailToken;
}

function readPositiveNumber(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === "") {
    return fallback;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function getAuthEmailTokenTtlMilliseconds(
  purpose: AuthEmailTokenPurpose
): number {
  if (purpose === AUTH_EMAIL_TOKEN_PURPOSE.PASSWORD_RESET) {
    const minutes = readPositiveNumber(
      process.env.PASSWORD_RESET_TOKEN_TTL_MINUTES,
      DEFAULT_PASSWORD_RESET_TTL_MINUTES
    );
    return minutes * 60 * 1000;
  }

  const hours = readPositiveNumber(
    process.env.INVITATION_TOKEN_TTL_HOURS,
    DEFAULT_INVITATION_TTL_HOURS
  );
  return hours * 60 * 60 * 1000;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** Create and persist a one-time token while returning the raw value once. */
export async function createAuthEmailToken(
  input: CreateAuthEmailTokenInput
): Promise<CreatedAuthEmailToken> {
  const token = randomBytes(32).toString("base64url");
  const createdAt = new Date();
  const expiresAt = new Date(
    createdAt.getTime() + getAuthEmailTokenTtlMilliseconds(input.purpose)
  );

  const record = await prisma.authEmailToken.create({
    data: {
      tokenHash: hashToken(token),
      purpose: input.purpose,
      email: normalizeEmail(input.email),
      authUserId: input.authUserId,
      organizationMemberId: input.organizationMemberId ?? null,
      requiresPassword: input.requiresPassword ?? false,
      expiresAt,
      createdAt,
    },
  });

  return { token, record };
}

/** Look up an unexpired, unconsumed token without consuming it. */
export async function findActiveAuthEmailToken(
  token: string,
  purpose: AuthEmailTokenPurpose
): Promise<AuthEmailToken | null> {
  if (typeof token !== "string" || token.length === 0) {
    return null;
  }

  return prisma.authEmailToken.findFirst({
    where: {
      tokenHash: hashToken(token),
      purpose,
      consumedAt: null,
      expiresAt: { gt: new Date() },
    },
  });
}

/**
 * Atomically claim a previously looked-up token. Only one concurrent caller
 * can receive a claim timestamp; all others receive null.
 */
export async function claimAuthEmailToken(recordId: string): Promise<Date | null> {
  const claimedAt = new Date();
  const result = await prisma.authEmailToken.updateMany({
    where: {
      id: recordId,
      consumedAt: null,
      expiresAt: { gt: claimedAt },
    },
    data: { consumedAt: claimedAt },
  });

  return result.count === 1 ? claimedAt : null;
}

/** Make a failed downstream claim usable again, guarded by its claim time. */
export async function releaseAuthEmailTokenClaim(
  recordId: string,
  claimedAt?: Date
): Promise<void> {
  await prisma.authEmailToken.updateMany({
    where: {
      id: recordId,
      consumedAt: claimedAt ?? { not: null },
      expiresAt: { gt: new Date() },
    },
    data: { consumedAt: null },
  });
}

/** Delete a token idempotently, typically when SMTP delivery fails. */
export async function deleteAuthEmailToken(recordId: string): Promise<void> {
  await prisma.authEmailToken.deleteMany({ where: { id: recordId } });
}

/**
 * Invalidate older tokens only after the current token has been delivered.
 * The createdAt guard prevents two concurrent deliveries from invalidating
 * each other and leaving the recipient with no usable link.
 */
export async function invalidateOtherAuthEmailTokens(
  record: Pick<
    AuthEmailToken,
    | "id"
    | "email"
    | "purpose"
    | "authUserId"
    | "organizationMemberId"
    | "createdAt"
  >
): Promise<void> {
  await prisma.authEmailToken.updateMany({
    where: {
      id: { not: record.id },
      email: normalizeEmail(record.email),
      purpose: record.purpose,
      ...(record.purpose === AUTH_EMAIL_TOKEN_PURPOSE.INVITATION
        ? { organizationMemberId: record.organizationMemberId }
        : { authUserId: record.authUserId }),
      consumedAt: null,
      createdAt: { lt: record.createdAt },
    },
    data: { consumedAt: new Date() },
  });
}

/** Invalidate every sibling token after an action has completed successfully. */
export async function invalidateAllOtherAuthEmailTokens(
  record: Pick<AuthEmailToken, "id" | "email" | "purpose" | "authUserId">
): Promise<void> {
  await prisma.authEmailToken.updateMany({
    where: {
      id: { not: record.id },
      email: normalizeEmail(record.email),
      purpose: record.purpose,
      authUserId: record.authUserId,
      consumedAt: null,
    },
    data: { consumedAt: new Date() },
  });
}
