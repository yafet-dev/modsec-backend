import { prisma } from "../lib/prisma";
import { enrichSeverity } from "./severityEnrichment";

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

interface ModsecTransaction {
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

/**
 * Finds organization ID by matching host against organization domains
 * Returns the organization ID if a match is found, null otherwise
 */
async function findOrganizationByHost(host: string): Promise<string | null> {
  if (!host || host === 'unknown') {
    return null;
  }

  try {
    // Normalize host: remove port if present, lowercase
    const normalizedHost = host.split(':')[0].toLowerCase().trim();

    // Find organization where the host matches one of the domains
    const organization = await prisma.organization.findFirst({
      where: {
        domains: {
          has: normalizedHost,
        },
        status: 'active', // Only match active organizations
      },
      select: {
        id: true,
      },
    });

    return organization?.id || null;
  } catch (error) {
    console.error(`Error finding organization for host ${host}:`, error);
    return null;
  }
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

  // Extract host from hostname or headers
  const host =
    transaction.request.hostname ||
    transaction.request.headers?.Host?.split(":")[0] ||
    "unknown";

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

/**
 * Processes a single modsec_landing record and creates a Log entry
 */
export async function processModsecLandingRecord(
  landingId: bigint | string,
  organizationId?: string
): Promise<{ success: boolean; logId?: string; error?: string }> {
  try {
    // Convert string to BigInt if needed
    const id = typeof landingId === 'string' ? BigInt(landingId) : landingId;
    
    // Fetch the modsec_landing record using id
    const landing = await prisma.modsecLanding.findUnique({
      where: {
        id: id,
      },
    });

    if (!landing) {
      return { success: false, error: "ModsecLanding record not found" };
    }

    if (landing.processed) {
      return { success: false, error: "Record already processed" };
    }

    // Parse the JSON data
    // Fluent Bit stores data in different formats:
    // 1. {"raw": "{\"transaction\":{...}}"} - raw JSON string
    // 2. {"data": "{\"transaction\":{...}}"} - nested data field
    // 3. {"transaction": {...}} - direct transaction
    let transactionData: ModsecTransaction;
    
    try {
      if (typeof landing.data === 'object' && landing.data !== null) {
        const dataObj = landing.data as any;
        let rawJsonText: string | null = null;
        
        // Try to extract raw JSON string (matching SQL script logic)
        // SQL script does: raw_json_text := row_record.data->>'raw';
        if (dataObj.raw && typeof dataObj.raw === 'string') {
          rawJsonText = dataObj.raw;
        } else if (dataObj.data && typeof dataObj.data === 'string') {
          // Fluent Bit stores as {"data": "..."}
          rawJsonText = dataObj.data;
        } else if (typeof dataObj === 'string') {
          // Sometimes the whole data field is a string
          rawJsonText = dataObj as string;
        }
        
        if (rawJsonText) {
          // Parse the raw JSON string
          try {
            const parsedJson = JSON.parse(rawJsonText);
            // Check if it has transaction directly or needs wrapping
            if (parsedJson.transaction) {
              transactionData = parsedJson as ModsecTransaction;
            } else {
              transactionData = { transaction: parsedJson } as ModsecTransaction;
            }
          } catch (parseError) {
            // If parsing fails, try unescaping
            let jsonString = rawJsonText;
            // Remove surrounding quotes if present
            if ((jsonString.startsWith('"') && jsonString.endsWith('"')) ||
                (jsonString.startsWith("'") && jsonString.endsWith("'"))) {
              jsonString = jsonString.slice(1, -1);
            }
            // Unescape common escape sequences
            jsonString = jsonString.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
            const parsedJson = JSON.parse(jsonString);
            transactionData = parsedJson.transaction 
              ? parsedJson as ModsecTransaction
              : { transaction: parsedJson } as ModsecTransaction;
          }
        } else if (dataObj.transaction) {
          // Direct transaction object
          transactionData = { transaction: dataObj.transaction } as ModsecTransaction;
        } else if (dataObj.data && typeof dataObj.data === 'object') {
          // Nested data object
          if (dataObj.data.transaction) {
            transactionData = dataObj.data as ModsecTransaction;
          } else {
            transactionData = { transaction: dataObj.data } as ModsecTransaction;
          }
        } else {
          // Try using the whole object as transaction
          transactionData = { transaction: dataObj } as ModsecTransaction;
        }
      } else {
        throw new Error("Data is not an object");
      }
    } catch (error) {
      console.error("Error parsing transaction data:", error);
      console.error("Data structure:", JSON.stringify(landing.data, null, 2));
      throw new Error(`Failed to parse transaction data: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
    
    // Validate that we have a transaction
    if (!transactionData || !transactionData.transaction) {
      throw new Error("Invalid transaction data structure - missing transaction");
    }

    // CRITICAL: Sanitize the entire transaction data structure before processing
    // This ensures all escape sequences in nested fields (like response.body, 
    // response.headers, messages[].details.match) are cleaned
    const sanitizedTransaction = sanitizeJson(transactionData);
    if (!sanitizedTransaction || !sanitizedTransaction.transaction) {
      throw new Error("Failed to sanitize transaction data");
    }

    // Extract host from transaction to find matching organization
    const host =
      sanitizedTransaction.transaction.request.hostname ||
      sanitizedTransaction.transaction.request.headers?.Host?.split(":")[0] ||
      sanitizedTransaction.transaction.request.headers?.host?.split(":")[0] ||
      "unknown";

    // Find organization by matching host against domains array
    // Use provided organizationId if available, otherwise lookup by host
    let finalOrganizationId: string | undefined = organizationId;
    if (!finalOrganizationId && host && host !== 'unknown') {
      const foundOrgId = await findOrganizationByHost(host);
      finalOrganizationId = foundOrgId || undefined;
    }

    // Transform to Log format using sanitized data and found organization ID
    const logEntry = transformModsecToLog(sanitizedTransaction, finalOrganizationId);

    // Final sanitization pass - ensure all fields are safe for PostgreSQL
    // This is critical - Prisma will serialize JSONB fields, and any escape sequences
    // in the data will cause PostgreSQL errors
    let safeLogEntry: any;
    try {
      // Stringify and re-parse to ensure clean JSON structure
      const stringified = JSON.stringify(logEntry);
      const parsed = JSON.parse(stringified);
      
      safeLogEntry = {
        ...parsed,
        // Re-sanitize JSON fields - deep clean all nested strings
        headers: parsed.headers ? sanitizeJson(parsed.headers) : null,
        responseHeader: parsed.responseHeader ? sanitizeJson(parsed.responseHeader) : null,
        // Re-sanitize all string fields
        rule: parsed.rule ? sanitizeString(parsed.rule) : null,
        ruleId: parsed.ruleId ? sanitizeString(parsed.ruleId) : null,
        userAgent: parsed.userAgent ? sanitizeString(parsed.userAgent) : null,
        message: parsed.message ? sanitizeString(parsed.message) : null,
        // Ensure required fields
        clientIp: parsed.clientIp || '0.0.0.0',
        host: parsed.host || 'unknown',
        method: parsed.method || 'GET',
        requestUrl: parsed.requestUrl || '/',
        action: parsed.action || 'warning',
        severity: parsed.severity || 'LOW',
      };
    } catch (sanitizeError) {
      console.error("Error during final sanitization:", sanitizeError);
      console.error("Original logEntry:", JSON.stringify(logEntry, null, 2));
      throw new Error(`Failed to sanitize log entry: ${sanitizeError instanceof Error ? sanitizeError.message : 'Unknown error'}`);
    }

    // Create Log entry with fully sanitized data
    // Wrap in try-catch to get better error details
    let log;
    try {
      log = await prisma.log.create({
        data: safeLogEntry,
      });
    } catch (createError: any) {
      // Log the problematic data for debugging
      console.error("Failed to create log entry. Problematic data:");
      console.error("Headers:", JSON.stringify(safeLogEntry.headers, null, 2));
      console.error("ResponseHeader:", JSON.stringify(safeLogEntry.responseHeader, null, 2));
      console.error("Rule:", safeLogEntry.rule);
      console.error("Message:", safeLogEntry.message);
      console.error("UserAgent:", safeLogEntry.userAgent);
      console.error("Full entry (sanitized):", JSON.stringify(safeLogEntry, null, 2));
      throw createError;
    }

    // Mark as processed using id
    await prisma.modsecLanding.update({
      where: {
        id: id,
      },
      data: { processed: true },
    });

    return { success: true, logId: log.id };
  } catch (error) {
    console.error("Error processing modsec_landing record:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Processes all unprocessed modsec_landing records
 */
export async function processAllModsecLandingRecords(
  organizationId?: string,
  batchSize: number = 100
): Promise<{
  processed: number;
  failed: number;
  errors: Array<{ id: string; error: string }>;
  logIds: string[]; // Return log IDs that were created
}> {
  const errors: Array<{ id: string; error: string }> = [];
  const logIds: string[] = [];
  let processed = 0;
  let failed = 0;

  try {
    let skip = 0;
    let hasMore = true;

    while (hasMore) {
      // Fetch unprocessed records in batches
      const records = await prisma.modsecLanding.findMany({
        where: { processed: false },
        take: batchSize,
        skip,
        orderBy: { time: "asc" },
      });

      if (records.length === 0) {
        hasMore = false;
        break;
      }

      // Process each record
      for (const record of records) {
        const result = await processModsecLandingRecord(
          record.id,
          organizationId
        );

        if (result.success) {
          processed++;
          if (result.logId) {
            logIds.push(result.logId);
          }
        } else {
          failed++;
          errors.push({ id: record.id.toString(), error: result.error || "Unknown error" });
        }
      }

      skip += batchSize;
      hasMore = records.length === batchSize;
    }

    return { processed, failed, errors, logIds };
  } catch (error) {
    console.error("Error processing modsec_landing records:", error);
    throw error;
  }
}

