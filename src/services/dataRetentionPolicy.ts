/**
 * Data retention rules shared by the settings API and the cleanup job.
 *
 * Two kinds of data are kept per organization:
 *
 *   - logs: organized WAF events in the "Log" table. These power the
 *     dashboard, logs page and summary reports.
 *   - raw:  unorganized ModSecurity JSON in "modsec_landing". Each row is
 *     copied into "Log" once processed, so it is only useful for
 *     troubleshooting and is by far the bulkiest data per event.
 *
 * Keep these values aligned with the CHECK constraints in
 * prisma/migrations/20261108120000_add_data_retention_settings.
 */

export interface RetentionLimit {
  /** Shortest retention an admin may choose, in days. */
  min: number;
  /** Longest retention an admin may choose, in days. */
  max: number;
  /** Value new organizations start with, in days. */
  default: number;
  /** Above this, the admin must acknowledge a database sizing warning. */
  recommendedMax: number;
}

export const RETENTION_LIMITS: { logs: RetentionLimit; raw: RetentionLimit } = {
  logs: { min: 7, max: 365, default: 30, recommendedMax: 90 },
  raw: { min: 7, max: 90, default: 30, recommendedMax: 90 },
};

export interface RetentionSettings {
  logRetentionDays: number;
  rawRetentionDays: number;
}

export interface RetentionUpdateInput {
  logRetentionDays?: unknown;
  rawRetentionDays?: unknown;
  acknowledgeStorageWarning?: unknown;
}

export type RetentionUpdateResult =
  | { ok: true; value: Partial<RetentionSettings> }
  | { ok: false; message: string; code?: "STORAGE_WARNING_NOT_ACKNOWLEDGED" };

function checkDays(
  value: unknown,
  field: string,
  limit: RetentionLimit
): { ok: true; days: number } | { ok: false; message: string } {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    return { ok: false, message: `${field} must be a whole number of days` };
  }
  if (value < limit.min || value > limit.max) {
    return {
      ok: false,
      message: `${field} must be between ${limit.min} and ${limit.max} days`,
    };
  }
  return { ok: true, days: value };
}

/**
 * Validate a PATCH body against the limits and the current settings.
 *
 * Raising log retention above the recommended maximum requires an explicit
 * acknowledgement. Lowering it, or saving an unchanged long retention, does
 * not, so an admin who already accepted the warning is not asked again for
 * unrelated edits.
 */
export function validateRetentionUpdate(
  input: RetentionUpdateInput,
  current: RetentionSettings
): RetentionUpdateResult {
  const value: Partial<RetentionSettings> = {};

  if (input.logRetentionDays === undefined && input.rawRetentionDays === undefined) {
    return {
      ok: false,
      message: "Provide logRetentionDays and/or rawRetentionDays",
    };
  }

  if (input.logRetentionDays !== undefined) {
    const checked = checkDays(input.logRetentionDays, "logRetentionDays", RETENTION_LIMITS.logs);
    if (!checked.ok) return checked;
    value.logRetentionDays = checked.days;
  }

  if (input.rawRetentionDays !== undefined) {
    const checked = checkDays(input.rawRetentionDays, "rawRetentionDays", RETENTION_LIMITS.raw);
    if (!checked.ok) return checked;
    value.rawRetentionDays = checked.days;
  }

  if (
    value.logRetentionDays !== undefined &&
    value.logRetentionDays > RETENTION_LIMITS.logs.recommendedMax &&
    value.logRetentionDays > current.logRetentionDays &&
    input.acknowledgeStorageWarning !== true
  ) {
    return {
      ok: false,
      code: "STORAGE_WARNING_NOT_ACKNOWLEDGED",
      message:
        `Keeping logs for more than ${RETENTION_LIMITS.logs.recommendedMax} days needs a larger ` +
        "database. Confirm your database meets the recommended size by sending " +
        "acknowledgeStorageWarning: true.",
    };
  }

  return { ok: true, value };
}

/**
 * Parse a days value from an environment variable, falling back to the
 * default and clamping into the allowed range.
 */
export function retentionDaysFromEnv(
  raw: string | undefined,
  limit: RetentionLimit
): number {
  const parsed = raw === undefined ? NaN : Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return limit.default;
  return Math.min(limit.max, Math.max(limit.min, parsed));
}

/** Retention for logs that could not be attributed to any organization. */
export function defaultLogRetentionDays(): number {
  return retentionDaysFromEnv(process.env.DEFAULT_LOG_RETENTION_DAYS, RETENTION_LIMITS.logs);
}

/** Retention for raw rows whose host does not belong to any organization. */
export function defaultRawRetentionDays(): number {
  return retentionDaysFromEnv(process.env.DEFAULT_RAW_RETENTION_DAYS, RETENTION_LIMITS.raw);
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** Rows strictly older than this instant are past retention. */
export function retentionCutoff(now: Date, days: number): Date {
  return new Date(now.getTime() - days * DAY_MS);
}

/**
 * Build the raw-retention policy for each normalized host.
 *
 * When two organizations claim the same host, the longer retention wins so
 * the cleanup never deletes data earlier than any claimant asked for.
 */
export function buildRawHostPolicy(
  organizations: Array<{ domains: string[]; rawRetentionDays: number }>,
  normalizeHost: (value: string) => string | null
): Map<string, number> {
  const policy = new Map<string, number>();
  for (const organization of organizations) {
    for (const domain of organization.domains) {
      const host = normalizeHost(domain);
      if (!host || host === "unknown") continue;
      const existing = policy.get(host);
      if (existing === undefined || organization.rawRetentionDays > existing) {
        policy.set(host, organization.rawRetentionDays);
      }
    }
  }
  return policy;
}
