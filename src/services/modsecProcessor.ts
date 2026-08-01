import { Prisma } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { normalizeModsecHostname } from "../utils/modsecHostname";
import { enrichSeverity } from "./severityEnrichment";

const MAX_LANDING_BATCH_SIZE = 1_000;
const TRANSACTION_MAX_WAIT_MS = 10_000;
const BULK_TRANSACTION_TIMEOUT_MS = 60_000;
const SINGLE_TRANSACTION_TIMEOUT_MS = 30_000;
const FALLBACK_CONCURRENCY = 4;
const ROW_LOCAL_BULK_ERROR_CODES = new Set([
  "P2000", // value too long for a column
  "P2004", // row-level database constraint
  "P2005", // invalid stored value
  "P2006", // invalid supplied value
  "P2007", // data validation error
  "P2011", // null constraint
  "P2012", // missing required value
  "P2019", // invalid input
  "P2020", // value out of range
]);

interface ModsecLandingRecord {
  id: bigint;
  data: Prisma.JsonValue;
  processed: boolean | null;
}

export interface ActiveOrganization {
  id: string;
  domains: string[];
}

interface PreparedLandingRecord {
  landingId: bigint;
  logData: Prisma.LogCreateManyInput;
}

interface LandingBatchResult {
  claimed: number;
  cursor: bigint | null;
  processed: number;
  failed: number;
  errors: Array<{ id: string; error: string }>;
  logIds: string[];
}

type OrganizationDomainIndex = Map<string, string | null>;

/**
 * Sanitize string fields to prevent Unicode escape sequence issues
 */
function sanitizeString(str: any): string | null {
  if (str === null || str === undefined) return null;
  if (typeof str !== 'string') {
    try {
      str = String(str);
    } catch {
      return null;
    }
  }
  
  // Remove problematic escape sequences that PostgreSQL doesn't like
  // CRITICAL: Remove null bytes first (both actual nulls and \u0000 escapes)
  let sanitized = str
    .replace(/\0/g, '') // Remove actual null bytes
    .replace(/\\u0000/g, '') // Remove \u0000 escape sequences
    .replace(/\\u0000/gi, '') // Case-insensitive removal
    .replace(/\\u([0-9a-fA-F]{4})/g, (match: string, hex: string) => {
      // Convert valid Unicode escapes to actual characters, but skip null
      try {
        const code = parseInt(hex, 16);
        if (code === 0) return ''; // Remove null bytes
        // Only allow printable characters and common control chars
        if (code >= 0x20 && code <= 0x7E) {
          return String.fromCharCode(code);
        } else if (code === 0x09 || code === 0x0A || code === 0x0D) {
          return String.fromCharCode(code);
        }
        return ''; // Remove other control characters
      } catch {
        return '';
      }
    });
  
  // Remove any remaining null bytes (in case they were created by the above)
  sanitized = sanitized.replace(/\0/g, '');
  
  // Remove any remaining problematic backslashes that aren't part of valid escapes
  // But preserve valid JSON escapes: ", \, /, b, f, n, r, t, uXXXX
  sanitized = sanitized.replace(/\\(?!["\\/bfnrtu0-9x])/g, '');
  
  // Remove triple+ backslashes that might cause issues (like \\\)
  sanitized = sanitized.replace(/\\\\\\+/g, '\\\\');
  
  // Remove any malformed Unicode escape sequences
  sanitized = sanitized.replace(/\\u[^0-9a-fA-F]/g, '');
  sanitized = sanitized.replace(/\\u[0-9a-fA-F]{0,3}(?![0-9a-fA-F])/g, '');
  
  return sanitized;
}

/**
 * Sanitize JSON fields to prevent escape sequence issues
 */
function sanitizeJson(obj: any): any {
  if (obj === null || obj === undefined) return null;
  
  try {
    let jsonObj: any;
    
    if (typeof obj === 'object' && !Array.isArray(obj) && obj.constructor === Object) {
      jsonObj = obj;
    } else if (typeof obj === 'string') {
      jsonObj = JSON.parse(obj);
    } else {
      jsonObj = JSON.parse(JSON.stringify(obj));
    }
    
    // Deep clean the object - recursively sanitize all string values
    // CRITICAL: This must remove \u0000 from all strings, especially in headers
    const cleanObject = (val: any): any => {
      if (val === null || val === undefined) return null;
      
      if (typeof val === 'string') {
        // Sanitize and double-check for null bytes
        let cleaned = sanitizeString(val);
        if (cleaned) {
          // Remove any remaining null bytes (both \0 and \u0000 patterns)
          cleaned = cleaned.replace(/\0/g, '').replace(/\\u0000/gi, '');
          return cleaned.length > 0 ? cleaned : null;
        }
        return null;
      } else if (Array.isArray(val)) {
        return val.map(cleanObject).filter(v => v !== null);
      } else if (typeof val === 'object' && val.constructor === Object) {
        const cleaned: any = {};
        for (const key in val) {
          if (val.hasOwnProperty(key)) {
            const cleanedValue = cleanObject(val[key]);
            if (cleanedValue !== null && cleanedValue !== undefined) {
              cleaned[key] = cleanedValue;
            }
          }
        }
        return cleaned;
      }
      return val;
    };
    
    return cleanObject(jsonObj);
  } catch (error) {
    console.warn("Failed to sanitize JSON:", error);
    return null;
  }
}

export interface ModsecTransaction {
  transaction: {
    client_ip: string;
    client_port?: number;
    time_stamp: string;
    host_ip?: string;
    host_port?: number;
    unique_id?: string;
    request: {
      method: string;
      http_version?: string;
      hostname: string;
      uri: string;
      headers: Record<string, string>;
    };
    response?: {
      http_code?: number;
      headers?: Record<string, string>;
      body?: string;
    };
    producer?: {
      modsecurity?: string;
      connector?: string;
      secrules_engine?: string;
      components?: string[];
    };
    messages?: Array<{
      message: string;
      details?: {
        ruleId?: string;
        severity?: string;
        maturity?: number;
        accuracy?: number;
        file?: string;
        lineNumber?: string;
        data?: string;
        match?: string;
        reference?: string;
        tags?: string[];
        ver?: string;
        rev?: string;
      };
    }>;
  };
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeJsonString(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch (firstError) {
    // Keep compatibility with legacy Fluent Bit rows that wrapped JSON in
    // quotes without encoding the outer value as valid JSON.
    let candidate = value.trim();
    if (
      (candidate.startsWith('"') && candidate.endsWith('"')) ||
      (candidate.startsWith("'") && candidate.endsWith("'"))
    ) {
      candidate = candidate.slice(1, -1);
    }
    candidate = candidate.replace(/\\"/g, '"').replace(/\\\\/g, "\\");

    try {
      return JSON.parse(candidate);
    } catch {
      throw firstError;
    }
  }
}

function unwrapLandingPayload(value: unknown, depth = 0): ModsecTransaction {
  if (depth > 4) {
    throw new Error("Landing data is nested too deeply");
  }

  if (typeof value === "string") {
    return unwrapLandingPayload(decodeJsonString(value), depth + 1);
  }

  if (!isRecord(value)) {
    throw new Error("Landing data must be a JSON object or encoded JSON string");
  }

  // Match the source-host database trigger's deterministic wrapper
  // precedence. A malformed `raw` value is a malformed row; silently falling
  // through to a second payload would make pending-host attribution disagree
  // with the Log ultimately created by this processor.
  if (typeof value.raw === "string") {
    return unwrapLandingPayload(value.raw, depth + 1);
  }
  if (typeof value.data === "string") {
    return unwrapLandingPayload(value.data, depth + 1);
  }
  if (isRecord(value.transaction)) {
    return { transaction: value.transaction } as ModsecTransaction;
  }
  if (isRecord(value.data)) {
    return unwrapLandingPayload(value.data, depth + 1);
  }

  // The remaining supported shape is the transaction object itself.
  if (isRecord(value.request)) {
    return { transaction: value } as ModsecTransaction;
  }

  throw new Error("Invalid transaction data structure - missing transaction");
}

/**
 * Decode every ModsecLanding JSON shape accepted by the processor.
 *
 * Kept pure so ingestion-format changes can be covered without a database.
 */
export function parseModsecLandingData(data: Prisma.JsonValue): ModsecTransaction {
  const parsed = unwrapLandingPayload(data);
  if (!isRecord(parsed.transaction) || !isRecord(parsed.transaction.request)) {
    throw new Error("Invalid transaction data structure - missing request");
  }
  return parsed;
}

function headerValue(
  headers: Record<string, unknown> | undefined,
  name: string
): string | null {
  if (!headers) return null;
  const entry = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === name.toLowerCase()
  );
  return typeof entry?.[1] === "string" ? entry[1] : null;
}

/** Backwards-compatible export; source-host SQL and APIs use the same helper. */
export const normalizeModsecHost = normalizeModsecHostname;

export function extractModsecHost(transactionData: ModsecTransaction): string {
  const request = transactionData.transaction.request;
  const normalizedHostname = normalizeModsecHost(request.hostname);
  const normalizedHostHeader = normalizeModsecHost(
    headerValue(request.headers as Record<string, unknown> | undefined, "host")
  );
  const hostname = normalizedHostname === "unknown" ? null : normalizedHostname;
  const hostHeader =
    normalizedHostHeader === "unknown" ? null : normalizedHostHeader;
  return hostname ?? hostHeader ?? "unknown";
}

/**
 * Maps ModSecurity severity to standard severity levels
 */
function mapSeverity(severity?: string): string {
  if (!severity) return "LOW";
  
  const severityNum = parseInt(severity);
  if (isNaN(severityNum)) return "LOW";
  
  if (severityNum >= 8) return "CRITICAL";
  if (severityNum >= 6) return "HIGH";
  if (severityNum >= 4) return "MEDIUM";
  return "LOW";
}

/**
 * Determines action based on response code and severity
 */
function determineAction(responseCode?: number, severity?: string): string {
  // If response code is 403 or 406, it's likely blocked
  if (responseCode === 403 || responseCode === 406) {
    return "blocked";
  }
  
  // If severity is high or critical, likely blocked
  const severityNum = severity ? parseInt(severity) : 0;
  if (severityNum >= 6) {
    return "blocked";
  }
  
  // Default to warning
  return "warning";
}

/**
 * Parses timestamp string to Date object
 */
function parseTimestamp(timeStamp: string): Date {
  try {
    // Try parsing the format: "Wed Dec 24 04:41:16 2025"
    const date = new Date(timeStamp);
    if (isNaN(date.getTime())) {
      // Fallback to current date if parsing fails
      return new Date();
    }
    return date;
  } catch {
    return new Date();
  }
}

function buildOrganizationDomainIndex(
  organizations: ActiveOrganization[]
): OrganizationDomainIndex {
  const index: OrganizationDomainIndex = new Map();

  for (const organization of organizations) {
    for (const rawDomain of organization.domains) {
      const domain = normalizeModsecHost(rawDomain);
      if (!domain || domain === "unknown") continue;

      const existing = index.get(domain);
      if (existing === undefined || existing === organization.id) {
        index.set(domain, organization.id);
      } else {
        // A duplicate domain claim is ambiguous. Refusing attribution is safer
        // than leaking one tenant's traffic into another tenant's Log rows.
        index.set(domain, null);
      }
    }
  }

  return index;
}

function resolveOrganizationFromIndex(
  host: string,
  index: OrganizationDomainIndex
): string | null {
  const normalizedHost = normalizeModsecHost(host);
  if (!normalizedHost || normalizedHost === "unknown") return null;
  return index.get(normalizedHost) ?? null;
}

/** Pure organization-host resolver used by tests and the batch processor. */
export function resolveOrganizationByHost(
  host: string,
  organizations: ActiveOrganization[]
): string | null {
  return resolveOrganizationFromIndex(host, buildOrganizationDomainIndex(organizations));
}

async function loadActiveOrganizationIndex(): Promise<OrganizationDomainIndex> {
  const organizations = await prisma.organization.findMany({
    where: { status: "active" },
    select: { id: true, domains: true },
  });
  return buildOrganizationDomainIndex(organizations);
}

/**
 * Transforms ModSecurity transaction JSON to Log format
 */
export function transformModsecToLog(
  transactionData: ModsecTransaction,
  organizationId?: string
) {
  const { transaction } = transactionData;
  const firstMessage = transaction.messages?.[0];
  const details = firstMessage?.details;

  const host = extractModsecHost(transactionData);

  // Extract user agent
  const userAgent =
    transaction.request.headers?.["User-Agent"] ||
    transaction.request.headers?.["user-agent"] ||
    null;

  // Enrich severity from anomaly score + attack tags (not raw ModSec severity)
  const enrichment = enrichSeverity(transaction.messages);
  const severity = enrichment.severity_normalized;

  // Determine action (still uses response code, but severity-based fallback now uses enriched severity)
  const action = determineAction(
    transaction.response?.http_code,
    enrichment.severity_normalized === "CRITICAL" ? "8" :
    enrichment.severity_normalized === "HIGH" ? "6" :
    enrichment.severity_normalized === "MEDIUM" ? "4" : "2"
  );

  // Parse timestamp
  const timestamp = parseTimestamp(transaction.time_stamp);

  // Build log entry with sanitized strings
  const logEntry = {
    organizationId: organizationId || null,
    action,
    severity,
    timestamp,
    clientIp: transaction.client_ip || '0.0.0.0',
    clientPort: transaction.client_port || null,
    host: host || 'unknown',
    method: transaction.request.method || 'GET',
    requestUrl: transaction.request.uri || '/',
    rule: sanitizeString(firstMessage?.message),
    ruleId: sanitizeString(details?.ruleId),
    userAgent: sanitizeString(userAgent),
    headers: sanitizeJson(transaction.request.headers),
    message: sanitizeString(
      firstMessage?.message
        ? `${firstMessage.message} [severity: ${enrichment.reason}]`
        : enrichment.reason
    ),
    httpMethod: transaction.request.http_version || null,
    // CRITICAL: responseHeader often contains \u0000 in Server header - must sanitize
    responseHeader: transaction.response?.headers 
      ? sanitizeJson(transaction.response.headers) 
      : null,
    responseCode: transaction.response?.http_code || null,
    maturity: details?.maturity ? parseInt(String(details.maturity)) : null,
  };

  return logEntry;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown error";
}

function shouldRetryBulkRowsIndividually(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientValidationError ||
    (error instanceof Prisma.PrismaClientKnownRequestError &&
      ROW_LOCAL_BULK_ERROR_CODES.has(error.code))
  );
}

function prepareLandingRecord(
  landing: ModsecLandingRecord,
  organizationId: string | undefined,
  organizationIndex: OrganizationDomainIndex
): PreparedLandingRecord {
  let transactionData: ModsecTransaction;
  try {
    transactionData = parseModsecLandingData(landing.data);
  } catch (error) {
    throw new Error(`Failed to parse transaction data: ${errorMessage(error)}`);
  }

  // Deep-clean before reading any nested request values. The same sanitized
  // transaction then drives host attribution and the final Log row.
  const sanitizedTransaction = sanitizeJson(transactionData) as
    | ModsecTransaction
    | null;
  if (
    !sanitizedTransaction?.transaction ||
    !sanitizedTransaction.transaction.request
  ) {
    throw new Error("Failed to sanitize transaction data");
  }

  const host = extractModsecHost(sanitizedTransaction);
  const finalOrganizationId =
    organizationId ??
    resolveOrganizationFromIndex(host, organizationIndex) ??
    undefined;
  const logEntry = transformModsecToLog(
    sanitizedTransaction,
    finalOrganizationId
  );

  try {
    // Preserve the existing final JSON round trip: it normalizes Date values
    // and catches values that Prisma's JSON serializer cannot persist.
    const parsed = JSON.parse(JSON.stringify(logEntry));
    const headers = parsed.headers ? sanitizeJson(parsed.headers) : null;
    const responseHeader = parsed.responseHeader
      ? sanitizeJson(parsed.responseHeader)
      : null;
    const logData: Prisma.LogCreateManyInput = {
      ...parsed,
      // Prisma distinguishes SQL NULL from a JSON `null` value. These columns
      // are optional, so missing/sanitized-away payloads belong in SQL NULL.
      headers: headers === null ? Prisma.DbNull : headers,
      responseHeader:
        responseHeader === null ? Prisma.DbNull : responseHeader,
      rule: parsed.rule ? sanitizeString(parsed.rule) : null,
      ruleId: parsed.ruleId ? sanitizeString(parsed.ruleId) : null,
      userAgent: parsed.userAgent ? sanitizeString(parsed.userAgent) : null,
      message: parsed.message ? sanitizeString(parsed.message) : null,
      clientIp: parsed.clientIp || "0.0.0.0",
      host: parsed.host || "unknown",
      method: parsed.method || "GET",
      requestUrl: parsed.requestUrl || "/",
      action: parsed.action || "warning",
      severity: parsed.severity || "LOW",
    };

    return { landingId: landing.id, logData };
  } catch (error) {
    throw new Error(`Failed to sanitize log entry: ${errorMessage(error)}`);
  }
}

export function normalizeLandingBatchSize(value: number): number {
  if (!Number.isFinite(value)) return 100;
  return Math.max(1, Math.min(MAX_LANDING_BATCH_SIZE, Math.trunc(value)));
}

async function processLockedLandingRecord(
  id: bigint,
  organizationId: string | undefined,
  organizationIndex: OrganizationDomainIndex
): Promise<{ success: boolean; logId?: string; error?: string }> {
  return prisma.$transaction(
    async (tx) => {
      const rows = await tx.$queryRaw<ModsecLandingRecord[]>(Prisma.sql`
        SELECT "id", "data", "processed"
        FROM "modsec_landing"
        WHERE "id" = ${id}
        FOR UPDATE
      `);
      const landing = rows[0];

      if (!landing) {
        return { success: false, error: "ModsecLanding record not found" };
      }
      if (landing.processed) {
        return { success: false, error: "Record already processed" };
      }
      if (landing.processed !== false) {
        return {
          success: false,
          error: "Record has no processable status (processed is null)",
        };
      }

      const prepared = prepareLandingRecord(
        landing,
        organizationId,
        organizationIndex
      );
      const log = await tx.log.create({ data: prepared.logData });
      const updated = await tx.modsecLanding.updateMany({
        where: { id, processed: false },
        data: { processed: true },
      });
      if (updated.count !== 1) {
        throw new Error("Landing record changed while it was being processed");
      }

      return { success: true, logId: log.id };
    },
    {
      maxWait: TRANSACTION_MAX_WAIT_MS,
      timeout: SINGLE_TRANSACTION_TIMEOUT_MS,
    }
  );
}

/**
 * Process one row under a database row lock. The Log insert and processed flag
 * commit together, so concurrent API/cron/worker callers cannot duplicate it.
 */
export async function processModsecLandingRecord(
  landingId: bigint | string,
  organizationId?: string
): Promise<{ success: boolean; logId?: string; error?: string }> {
  try {
    const id = typeof landingId === "string" ? BigInt(landingId) : landingId;
    const organizationIndex = organizationId
      ? new Map<string, string | null>()
      : await loadActiveOrganizationIndex();
    return await processLockedLandingRecord(
      id,
      organizationId,
      organizationIndex
    );
  } catch (error) {
    console.error("Error processing modsec_landing record:", error);
    return { success: false, error: errorMessage(error) };
  }
}

async function mapWithConcurrency<T, R>(
  values: T[],
  concurrency: number,
  task: (value: T) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let nextIndex = 0;

  const worker = async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= values.length) return;
      results[index] = await task(values[index]);
    }
  };

  await Promise.all(
    Array.from(
      { length: Math.min(Math.max(1, concurrency), values.length) },
      worker
    )
  );
  return results;
}

async function fallbackClaimedRecords(
  ids: bigint[],
  organizationId: string | undefined,
  organizationIndex: OrganizationDomainIndex
): Promise<LandingBatchResult> {
  const outcomes = await mapWithConcurrency(
    ids,
    FALLBACK_CONCURRENCY,
    async (id) => {
      try {
        return await processLockedLandingRecord(
          id,
          organizationId,
          organizationIndex
        );
      } catch (error) {
        return { success: false, error: errorMessage(error) };
      }
    }
  );

  const errors: Array<{ id: string; error: string }> = [];
  const logIds: string[] = [];
  let processed = 0;

  outcomes.forEach((outcome, index) => {
    if (outcome.success) {
      processed++;
      if (outcome.logId) logIds.push(outcome.logId);
      return;
    }

    // A concurrent worker may have committed after the failed bulk transaction
    // released its locks. That row is complete, not a failure for this run.
    if (outcome.error === "Record already processed") return;
    errors.push({ id: ids[index].toString(), error: outcome.error ?? "Unknown error" });
  });

  return {
    claimed: ids.length,
    cursor: ids.at(-1) ?? null,
    processed,
    failed: errors.length,
    errors,
    logIds,
  };
}

async function processClaimedBatch(
  afterId: bigint,
  throughId: bigint,
  batchSize: number,
  organizationId: string | undefined,
  organizationIndex: OrganizationDomainIndex
): Promise<LandingBatchResult> {
  let claimedIds: bigint[] = [];

  try {
    return await prisma.$transaction(
      async (tx) => {
        const records = await tx.$queryRaw<ModsecLandingRecord[]>(Prisma.sql`
          SELECT "id", "data", "processed"
          FROM "modsec_landing"
          WHERE "processed" = false
            AND "id" > ${afterId}
            AND "id" <= ${throughId}
          ORDER BY "id" ASC
          LIMIT ${batchSize}
          FOR UPDATE SKIP LOCKED
        `);
        claimedIds = records.map((record) => record.id);
        if (records.length === 0) {
          return {
            claimed: 0,
            cursor: null,
            processed: 0,
            failed: 0,
            errors: [],
            logIds: [],
          };
        }

        const prepared: PreparedLandingRecord[] = [];
        const errors: Array<{ id: string; error: string }> = [];
        for (const record of records) {
          try {
            prepared.push(
              prepareLandingRecord(record, organizationId, organizationIndex)
            );
          } catch (error) {
            errors.push({ id: record.id.toString(), error: errorMessage(error) });
          }
        }

        let logIds: string[] = [];
        if (prepared.length > 0) {
          const created = await tx.log.createManyAndReturn({
            data: prepared.map((item) => item.logData),
            select: { id: true },
          });
          if (created.length !== prepared.length) {
            throw new Error("Bulk insert returned an unexpected number of logs");
          }

          const updated = await tx.modsecLanding.updateMany({
            where: {
              id: { in: prepared.map((item) => item.landingId) },
              processed: false,
            },
            data: { processed: true },
          });
          if (updated.count !== prepared.length) {
            throw new Error("Bulk landing update count did not match log inserts");
          }
          logIds = created.map((log) => log.id);
        }

        return {
          claimed: records.length,
          cursor: records[records.length - 1].id,
          processed: prepared.length,
          failed: errors.length,
          errors,
          logIds,
        };
      },
      {
        maxWait: TRANSACTION_MAX_WAIT_MS,
        timeout: BULK_TRANSACTION_TIMEOUT_MS,
      }
    );
  } catch (bulkError) {
    if (
      claimedIds.length === 0 ||
      !shouldRetryBulkRowsIndividually(bulkError)
    ) {
      throw bulkError;
    }
    console.warn(
      `Bulk ModsecLanding batch failed; retrying ${claimedIds.length} rows individually:`,
      errorMessage(bulkError)
    );
    return fallbackClaimedRecords(
      claimedIds,
      organizationId,
      organizationIndex
    );
  }
}

/**
 * Drain the pending landing table in monotonic keyset batches.
 *
 * Parse failures advance the in-run cursor but remain processed=false, so they
 * are reported once per run and cannot starve later valid rows. A future run
 * retries them after an operator fixes the malformed payload.
 */
export async function processAllModsecLandingRecords(
  organizationId?: string,
  batchSize: number = 100
): Promise<{
  processed: number;
  failed: number;
  errors: Array<{ id: string; error: string }>;
  logIds: string[];
}> {
  const size = normalizeLandingBatchSize(batchSize);
  const errors: Array<{ id: string; error: string }> = [];
  const logIds: string[] = [];
  let processed = 0;
  let failed = 0;
  let cursor = 0n;

  try {
    // Bound this invocation to the backlog visible at start. Continuous
    // ingestion is left for the next scheduled run, keeping notifications and
    // accumulated result arrays finite under sustained traffic.
    const pendingAtStart = await prisma.modsecLanding.aggregate({
      where: { processed: false },
      _max: { id: true },
    });
    const throughId = pendingAtStart._max.id;
    if (throughId === null) {
      return { processed, failed, errors, logIds };
    }
    const organizationIndex = organizationId
      ? new Map<string, string | null>()
      : await loadActiveOrganizationIndex();

    while (true) {
      let batch: LandingBatchResult;
      try {
        batch = await processClaimedBatch(
          cursor,
          throughId,
          size,
          organizationId,
          organizationIndex
        );
      } catch (error) {
        // Earlier batches are already committed. Return their IDs so callers
        // still deliver notifications, and record where the drain stopped so
        // the next run can retry the untouched suffix.
        if (processed > 0 || failed > 0 || logIds.length > 0) {
          failed++;
          errors.push({
            id: `batch-after-${cursor.toString()}`,
            error: `Processing stopped before the initial backlog was drained: ${errorMessage(error)}`,
          });
          console.error("ModsecLanding drain stopped after partial progress:", error);
          return { processed, failed, errors, logIds };
        }
        throw error;
      }
      if (batch.claimed === 0 || batch.cursor === null) break;

      processed += batch.processed;
      failed += batch.failed;
      errors.push(...batch.errors);
      logIds.push(...batch.logIds);
      cursor = batch.cursor;

      // A short final page is the end of this keyset snapshot. Rows skipped
      // because another worker holds their locks are owned by that worker.
      if (batch.claimed < size) break;
    }

    return { processed, failed, errors, logIds };
  } catch (error) {
    console.error("Error processing modsec_landing records:", error);
    throw error;
  }
}

