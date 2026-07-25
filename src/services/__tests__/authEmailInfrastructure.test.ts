import assert from "node:assert/strict";
import {
  existsSync,
  readFileSync,
  readdirSync,
  type Dirent,
} from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  getSmtpConfig,
  parseSmtpPort,
  parseSmtpRequireTls,
  parseSmtpSecure,
} from "../../lib/email";
import { normalizeEmail } from "../../utils/normalizeEmail";
import { buildAuthEmailLink } from "../authEmailService";
import {
  AUTH_EMAIL_TOKEN_PURPOSE,
  getAuthEmailTokenTtlMilliseconds,
} from "../authEmailTokenService";

const backendRoot = path.resolve(__dirname, "../../..");
const workspaceRoot = path.dirname(backendRoot);

function withEnvironment(
  overrides: Record<string, string | undefined>,
  callback: () => void
): void {
  const original = new Map<string, string | undefined>();

  for (const [name, value] of Object.entries(overrides)) {
    original.set(name, process.env[name]);
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }

  try {
    callback();
  } finally {
    for (const [name, value] of original) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}

function applicationSourceFiles(directory: string): string[] {
  if (!existsSync(directory)) return [];

  const ignoredDirectories = new Set([
    ".git",
    ".next",
    "__tests__",
    "dist",
    "node_modules",
  ]);

  return readdirSync(directory, { withFileTypes: true }).flatMap(
    (entry: Dirent): string[] => {
      const absolutePath = path.join(directory, entry.name);

      if (entry.isDirectory()) {
        return ignoredDirectories.has(entry.name)
          ? []
          : applicationSourceFiles(absolutePath);
      }

      return entry.isFile() && /\.(?:js|jsx|ts|tsx)$/.test(entry.name)
        ? [absolutePath]
        : [];
    }
  );
}

test("normalizeEmail trims and canonicalizes auth identities", () => {
  assert.equal(normalizeEmail("  Mixed.Case+tag@Example.COM  "), "mixed.case+tag@example.com");
  assert.throws(() => normalizeEmail("   "), /Email is required/);
  assert.throws(
    () => normalizeEmail(null as unknown as string),
    /Email must be a string/
  );
});

test("auth links use FRONTEND_URL and safely encode opaque tokens", () => {
  withEnvironment(
    { FRONTEND_URL: "https://console.example.test/" },
    () => {
      const opaqueToken = "opaque+/=?&value#fragment";
      const link = buildAuthEmailLink("/reset-password", opaqueToken);

      assert.equal(
        link,
        "https://console.example.test/reset-password#token=opaque%2B%2F%3D%3F%26value%23fragment"
      );
      assert.equal(
        new URLSearchParams(new URL(link).hash.slice(1)).get("token"),
        opaqueToken
      );
    }
  );
});

test("auth token TTLs use defaults, valid env values, and invalid fallbacks", () => {
  withEnvironment(
    {
      PASSWORD_RESET_TOKEN_TTL_MINUTES: undefined,
      INVITATION_TOKEN_TTL_HOURS: undefined,
    },
    () => {
      assert.equal(
        getAuthEmailTokenTtlMilliseconds(
          AUTH_EMAIL_TOKEN_PURPOSE.PASSWORD_RESET
        ),
        60 * 60 * 1000
      );
      assert.equal(
        getAuthEmailTokenTtlMilliseconds(AUTH_EMAIL_TOKEN_PURPOSE.INVITATION),
        72 * 60 * 60 * 1000
      );
    }
  );

  withEnvironment(
    {
      PASSWORD_RESET_TOKEN_TTL_MINUTES: "15",
      INVITATION_TOKEN_TTL_HOURS: "24",
    },
    () => {
      assert.equal(
        getAuthEmailTokenTtlMilliseconds(
          AUTH_EMAIL_TOKEN_PURPOSE.PASSWORD_RESET
        ),
        15 * 60 * 1000
      );
      assert.equal(
        getAuthEmailTokenTtlMilliseconds(AUTH_EMAIL_TOKEN_PURPOSE.INVITATION),
        24 * 60 * 60 * 1000
      );
    }
  );

  withEnvironment(
    {
      PASSWORD_RESET_TOKEN_TTL_MINUTES: "not-a-number",
      INVITATION_TOKEN_TTL_HOURS: "0",
    },
    () => {
      assert.equal(
        getAuthEmailTokenTtlMilliseconds(
          AUTH_EMAIL_TOKEN_PURPOSE.PASSWORD_RESET
        ),
        60 * 60 * 1000
      );
      assert.equal(
        getAuthEmailTokenTtlMilliseconds(AUTH_EMAIL_TOKEN_PURPOSE.INVITATION),
        72 * 60 * 60 * 1000
      );
    }
  );
});

test("SMTP config honors SMTP_FROM and SMTP_FROM_NAME", () => {
  assert.deepEqual(
    getSmtpConfig({
      SMTP_HOST: " smtp.example.test ",
      SMTP_PORT: "2525",
      SMTP_SECURE: "true",
      SMTP_USER: "mailer@example.test",
      SMTP_PASS: "secret",
      SMTP_FROM: "Ignored Name <no-reply@example.test>",
      SMTP_FROM_NAME: " Zergaw Security ",
    }),
    {
      host: "smtp.example.test",
      port: 2525,
      secure: true,
      requireTls: true,
      user: "mailer@example.test",
      pass: "secret",
      fromAddress: "no-reply@example.test",
      fromName: "Zergaw Security",
    }
  );
});

test("SMTP config supports EMAIL_FROM and authenticated-user fallbacks", () => {
  assert.deepEqual(
    getSmtpConfig({
      SMTP_HOST: "smtp.example.test",
      SMTP_USER: "mailer@example.test",
      SMTP_PASS: "secret",
      EMAIL_FROM: "Legacy Sender <legacy@example.test>",
    }),
    {
      host: "smtp.example.test",
      port: 587,
      secure: false,
      requireTls: true,
      user: "mailer@example.test",
      pass: "secret",
      fromAddress: "legacy@example.test",
      fromName: "Legacy Sender",
    }
  );

  assert.deepEqual(
    getSmtpConfig({
      SMTP_HOST: "smtp.example.test",
      SMTP_USER: "mailer@example.test",
      SMTP_PASS: "secret",
    }),
    {
      host: "smtp.example.test",
      port: 587,
      secure: false,
      requireTls: true,
      user: "mailer@example.test",
      pass: "secret",
      fromAddress: "mailer@example.test",
      fromName: "Zergaw Cloud Firewall",
    }
  );
});

test("SMTP port and secure parsing reject invalid configuration", () => {
  for (const invalidPort of ["0", "65536", "587.5", "not-a-port"]) {
    assert.throws(
      () => parseSmtpPort(invalidPort),
      /SMTP_PORT must be an integer between 1 and 65535/
    );
  }

  assert.equal(parseSmtpSecure(undefined, 465), true);
  assert.equal(parseSmtpSecure(undefined, 587), false);
  assert.equal(parseSmtpSecure("true", 587), true);
  assert.equal(parseSmtpSecure("false", 465), false);
  assert.throws(
    () => parseSmtpSecure("yes", 587),
    /SMTP_SECURE must be either "true" or "false"/
  );
  assert.equal(parseSmtpRequireTls(undefined), true);
  assert.equal(parseSmtpRequireTls("true"), true);
  assert.equal(parseSmtpRequireTls("false"), false);
  assert.throws(
    () => parseSmtpRequireTls("yes"),
    /SMTP_REQUIRE_TLS must be either "true" or "false"/
  );
});

test("application source has no Supabase-owned auth email callsites", () => {
  const sourceFiles = [
    ...applicationSourceFiles(path.join(backendRoot, "src")),
    ...applicationSourceFiles(path.join(backendRoot, "prisma")),
    ...applicationSourceFiles(path.join(workspaceRoot, "modsec-ui")),
  ];
  const forbiddenCallsites: string[] = [];

  for (const filename of sourceFiles) {
    const source = readFileSync(filename, "utf8");
    const relativeFilename = path.relative(workspaceRoot, filename);

    if (/\binviteUserByEmail\s*\(/.test(source)) {
      forbiddenCallsites.push(`${relativeFilename}: inviteUserByEmail`);
    }
    if (/\bresetPasswordForEmail\s*\(/.test(source)) {
      forbiddenCallsites.push(`${relativeFilename}: resetPasswordForEmail`);
    }
    if (
      path.resolve(filename) === path.join(backendRoot, "prisma", "seed.ts") &&
      /\.auth\s*\.\s*signUp\s*\(/.test(source)
    ) {
      forbiddenCallsites.push(`${relativeFilename}: non-admin auth.signUp`);
    }
  }

  assert.deepEqual(forbiddenCallsites, []);
});
