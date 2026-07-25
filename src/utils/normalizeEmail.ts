/**
 * Return the canonical email representation used for auth lookups and tokens.
 * Supabase treats email identities case-insensitively, so application records
 * must use the same trimmed, lower-case form when they are compared.
 */
export function normalizeEmail(email: string): string {
  if (typeof email !== "string") {
    throw new TypeError("Email must be a string");
  }

  const normalized = email.trim().toLowerCase();

  if (!normalized) {
    throw new Error("Email is required");
  }

  return normalized;
}
