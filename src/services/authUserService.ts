import { randomBytes } from "crypto";
import type { User as SupabaseUser } from "@supabase/supabase-js";
import { supabaseAdmin } from "../lib/supabase";
import { normalizeEmail } from "../utils/normalizeEmail";

const AUTH_USER_PAGE_SIZE = 1000;

export { normalizeEmail } from "../utils/normalizeEmail";

export interface EnsureSupabaseAuthUserInput {
  email: string;
  userMetadata?: Record<string, unknown>;
}

export interface EnsureSupabaseAuthUserResult {
  authUser: SupabaseUser;
  created: boolean;
  requiresPassword: boolean;
}

function requireSupabaseAdmin() {
  if (!supabaseAdmin) {
    throw new Error("SUPABASE_SERVICE_ROLE_KEY is required for auth user administration");
  }

  return supabaseAdmin;
}

function createTemporaryPassword(): string {
  // 256 random bits plus explicit character classes comfortably exceeds
  // Supabase's password requirements. The value is never persisted or returned.
  return `${randomBytes(32).toString("base64url")}Aa1!`;
}

function existingUserRequiresPassword(user: SupabaseUser): boolean {
  // Users created for an invitation have a random, unknown password and remain
  // unconfirmed until they accept. This also makes re-sent invitations safe.
  return !user.email_confirmed_at && !user.confirmed_at;
}

/**
 * Find an auth user without triggering any Supabase email. Supabase's admin
 * endpoint is paginated, so every page is searched until the user or the end
 * of the collection is reached.
 */
export async function findSupabaseAuthUserByEmail(
  email: string
): Promise<SupabaseUser | null> {
  const normalizedEmail = normalizeEmail(email);
  const admin = requireSupabaseAdmin();

  for (let page = 1; ; page += 1) {
    const { data, error } = await admin.auth.admin.listUsers({
      page,
      perPage: AUTH_USER_PAGE_SIZE,
    });

    if (error) {
      throw new Error(`Unable to list Supabase auth users: ${error.message}`);
    }

    const users = data.users ?? [];
    const authUser = users.find(
      (user) =>
        typeof user.email === "string" &&
        normalizeEmail(user.email) === normalizedEmail
    );

    if (authUser) {
      return authUser;
    }

    if (users.length < AUTH_USER_PAGE_SIZE) {
      return null;
    }
  }
}

/**
 * Ensure an email identity exists in Supabase Auth without using Supabase's
 * invite/reset mailers. New users receive an unguessable temporary password;
 * only the application-owned token flow can let them replace it.
 */
export async function ensureSupabaseAuthUser(
  input: EnsureSupabaseAuthUserInput
): Promise<EnsureSupabaseAuthUserResult> {
  const email = normalizeEmail(input.email);
  const existingUser = await findSupabaseAuthUserByEmail(email);

  if (existingUser) {
    return {
      authUser: existingUser,
      created: false,
      requiresPassword: existingUserRequiresPassword(existingUser),
    };
  }

  const admin = requireSupabaseAdmin();
  const { data, error } = await admin.auth.admin.createUser({
    email,
    password: createTemporaryPassword(),
    email_confirm: false,
    user_metadata: input.userMetadata,
  });

  if (error || !data.user) {
    // A concurrent request may have created this identity after our lookup.
    // Re-read before surfacing the create error so invitation retries remain
    // idempotent without ever switching to a Supabase email-sending endpoint.
    const concurrentlyCreatedUser = await findSupabaseAuthUserByEmail(email);

    if (concurrentlyCreatedUser) {
      return {
        authUser: concurrentlyCreatedUser,
        created: false,
        requiresPassword: existingUserRequiresPassword(concurrentlyCreatedUser),
      };
    }

    throw new Error(
      `Unable to create Supabase auth user: ${error?.message ?? "No user returned"}`
    );
  }

  return {
    authUser: data.user,
    created: true,
    requiresPassword: true,
  };
}
