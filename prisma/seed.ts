import { PrismaClient } from "@prisma/client";
import { createClient, User as SupabaseUser } from "@supabase/supabase-js";
import * as dotenv from "dotenv";

dotenv.config();

const prisma = new PrismaClient();

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} must be set in the backend .env file`);
  }
  return value;
}

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (!normalized) {
    throw new Error("ADMIN_EMAIL must not be empty");
  }
  return normalized;
}

const supabase = createClient(
  requiredEnv("SUPABASE_URL"),
  requiredEnv("SUPABASE_SERVICE_ROLE_KEY"),
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

async function findAuthUserByEmail(
  normalizedEmail: string
): Promise<SupabaseUser | null> {
  const perPage = 100;

  for (let page = 1; ; page += 1) {
    const { data, error } = await supabase.auth.admin.listUsers({
      page,
      perPage,
    });

    if (error) {
      throw new Error(`Could not query Supabase Auth users: ${error.message}`);
    }

    const matches = data.users.filter(
      (user) => user.email?.trim().toLowerCase() === normalizedEmail
    );

    if (matches.length > 1) {
      throw new Error(
        `Multiple Supabase Auth users match ${normalizedEmail}; resolve the duplicate before seeding`
      );
    }
    if (matches.length === 1) {
      return matches[0];
    }
    if (data.users.length < perPage) {
      return null;
    }
  }
}

async function getMappedAuthUser(
  authUserId: string | null
): Promise<SupabaseUser | null> {
  if (!authUserId) return null;

  const { data, error } = await supabase.auth.admin.getUserById(authUserId);
  if (error) {
    const status = (error as { status?: number }).status;
    if (status === 404) return null;
    throw new Error(
      `Could not query mapped Supabase Auth user ${authUserId}: ${error.message}`
    );
  }

  return data.user;
}

async function createOrUpdateAuthUser(options: {
  email: string;
  password: string;
  fullName: string;
  mappedAuthUserId: string | null;
}): Promise<{ user: SupabaseUser; created: boolean }> {
  const byEmail = await findAuthUserByEmail(options.email);

  if (
    byEmail &&
    options.mappedAuthUserId &&
    byEmail.id !== options.mappedAuthUserId
  ) {
    throw new Error(
      `Local user maps to Supabase Auth user ${options.mappedAuthUserId}, but ${options.email} belongs to ${byEmail.id}`
    );
  }

  const mappedUser = byEmail
    ? null
    : await getMappedAuthUser(options.mappedAuthUserId);
  const existingAuthUser = byEmail || mappedUser;
  const userMetadata = {
    ...(existingAuthUser?.user_metadata || {}),
    full_name: options.fullName,
  };

  if (existingAuthUser) {
    const { data, error } = await supabase.auth.admin.updateUserById(
      existingAuthUser.id,
      {
        email: options.email,
        password: options.password,
        email_confirm: true,
        user_metadata: userMetadata,
      }
    );

    if (error || !data.user) {
      throw new Error(
        `Could not update Supabase Auth admin: ${
          error?.message || "no user returned"
        }`
      );
    }

    return { user: data.user, created: false };
  }

  // Admin createUser with email_confirm=true creates a ready-to-use identity
  // without invoking Supabase's confirmation email delivery.
  const { data, error } = await supabase.auth.admin.createUser({
    email: options.email,
    password: options.password,
    email_confirm: true,
    user_metadata: userMetadata,
  });

  if (error || !data.user) {
    throw new Error(
      `Could not create Supabase Auth admin: ${
        error?.message || "no user returned"
      }`
    );
  }

  return { user: data.user, created: true };
}

async function main(): Promise<void> {
  console.log("Starting seed...");

  const adminEmail = normalizeEmail(requiredEnv("ADMIN_EMAIL"));
  const adminPassword = requiredEnv("ADMIN_PASSWORD");
  const adminFullName = process.env.ADMIN_FULL_NAME?.trim() || "Super Admin";

  const localMatches = await prisma.user.findMany({
    where: {
      email: {
        equals: adminEmail,
        mode: "insensitive",
      },
    },
    take: 2,
  });

  if (localMatches.length > 1) {
    throw new Error(
      `Multiple local users match ${adminEmail}; resolve the duplicate before seeding`
    );
  }

  const existingLocalUser = localMatches[0] || null;

  // Complete the external Auth operation before any local database write. This
  // prevents the seed from ever creating a database-only login identity after
  // an Auth failure.
  const authResult = await createOrUpdateAuthUser({
    email: adminEmail,
    password: adminPassword,
    fullName: adminFullName,
    mappedAuthUserId: existingLocalUser?.authUserId || null,
  });

  const mappingConflict = await prisma.user.findUnique({
    where: { authUserId: authResult.user.id },
  });
  if (
    mappingConflict &&
    (!existingLocalUser || mappingConflict.id !== existingLocalUser.id)
  ) {
    throw new Error(
      `Supabase Auth user ${authResult.user.id} is already mapped to local user ${mappingConflict.id}`
    );
  }

  const user = existingLocalUser
    ? await prisma.user.update({
        where: { id: existingLocalUser.id },
        data: {
          email: adminEmail,
          fullName: adminFullName,
          role: "super_admin",
          authUserId: authResult.user.id,
        },
      })
    : await prisma.user.create({
        data: {
          id: process.env.ADMIN_ID?.trim() || authResult.user.id,
          authUserId: authResult.user.id,
          email: adminEmail,
          fullName: adminFullName,
          role: "super_admin",
        },
      });

  console.log(
    `${authResult.created ? "Created" : "Updated"} Supabase Auth identity without sending a confirmation email.`
  );
  console.log(
    `${existingLocalUser ? "Updated" : "Created"} local super admin ${user.email} (local ID: ${user.id}, auth ID: ${authResult.user.id}).`
  );
  console.log("Seed completed successfully.");
}

main()
  .catch((error) => {
    console.error("Seed failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
