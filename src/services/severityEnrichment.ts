/**
 * Severity Enrichment for ModSecurity Events
 *
 * Computes normalized severity from anomaly score + attack tags,
 * NOT from the raw ModSecurity numeric severity field.
 *
 * Pure function: (messages) => enrichment
 */

export interface ModsecMessageInput {
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
}

export type ImpactLevel =
  | "CRITICAL_IMPACT"
  | "HIGH_IMPACT"
  | "MEDIUM_IMPACT"
  | "LOW_IMPACT";

export type ConfidenceLevel =
  | "LOW_CONF"
  | "MEDIUM_CONF"
  | "HIGH_CONF"
  | "VERY_HIGH_CONF";

export type NormalizedSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface SeverityEnrichment {
  anomaly_score: number;
  tags_all: string[];
  impact_level: ImpactLevel;
  confidence_level: ConfidenceLevel;
  severity_normalized: NormalizedSeverity;
  reason: string;
}

const CRITICAL_IMPACT_TAGS = new Set([
  "attack-rce",
  "attack-sqli",
  "attack-lfi",
  "attack-rfi",
  "attack-ssrf",
  "attack-deserialization",
  "attack-injection",
]);

const HIGH_IMPACT_TAGS = new Set([
  "attack-xss",
  "attack-session-fixation",
  "attack-protocol",
  "attack-java",
  "attack-php",
]);

/**
 * Extract the anomaly score from the "Inbound Anomaly Score Exceeded" message.
 * Returns 0 if not found.
 */
function extractAnomalyScore(messages: ModsecMessageInput[]): number {
  for (const msg of messages) {
    if (!msg.message) continue;
    const match = msg.message.match(
      /Inbound Anomaly Score Exceeded.*?\(Total Score:\s*(\d+)\)/i
    );
    if (match) {
      const parsed = parseInt(match[1], 10);
      return isNaN(parsed) ? 0 : parsed;
    }
  }
  return 0;
}

/**
 * Collect all tags from every message's details.tags into a unique set.
 */
function collectAllTags(messages: ModsecMessageInput[]): string[] {
  const tagSet = new Set<string>();
  for (const msg of messages) {
    if (msg.details?.tags && Array.isArray(msg.details.tags)) {
      for (const tag of msg.details.tags) {
        if (typeof tag === "string" && tag.length > 0) {
          tagSet.add(tag);
        }
      }
    }
  }
  return Array.from(tagSet);
}

/**
 * Determine impact level from the collected tags.
 */
function determineImpactLevel(
  tagsAll: string[],
  hasMessages: boolean
): ImpactLevel {
  const hasCritical = tagsAll.some((tag) => CRITICAL_IMPACT_TAGS.has(tag));
  if (hasCritical) return "CRITICAL_IMPACT";

  const hasHigh = tagsAll.some((tag) => HIGH_IMPACT_TAGS.has(tag));
  if (hasHigh) return "HIGH_IMPACT";

  if (hasMessages) return "MEDIUM_IMPACT";

  return "LOW_IMPACT";
}

/**
 * Determine confidence level from anomaly score.
 */
function determineConfidenceLevel(anomalyScore: number): ConfidenceLevel {
  if (anomalyScore >= 20) return "VERY_HIGH_CONF";
  if (anomalyScore >= 10) return "HIGH_CONF";
  if (anomalyScore >= 5) return "MEDIUM_CONF";
  return "LOW_CONF";
}

/**
 * Enrich a ModSecurity event with normalized severity.
 *
 * @param messages - The transaction.messages array (may be undefined/null/empty)
 * @returns SeverityEnrichment object with anomaly_score, tags, impact, confidence, severity, reason
 */
export function enrichSeverity(
  messages?: ModsecMessageInput[] | null
): SeverityEnrichment {
  const safeMessages =
    messages && Array.isArray(messages) ? messages : [];
  const hasMessages = safeMessages.length > 0;

  // 1) Extract anomaly score
  const anomaly_score = hasMessages
    ? extractAnomalyScore(safeMessages)
    : 0;

  // 2) Build tags_all
  const tags_all = hasMessages ? collectAllTags(safeMessages) : [];

  // 3) Impact level
  const impact_level = determineImpactLevel(tags_all, hasMessages);

  // 4) Confidence level
  const confidence_level = determineConfidenceLevel(anomaly_score);

  // Helper: notable tags for the reason string
  const criticalTagsFound = tags_all.filter((t) => CRITICAL_IMPACT_TAGS.has(t));
  const highTagsFound = tags_all.filter((t) => HIGH_IMPACT_TAGS.has(t));
  const notableTag =
    criticalTagsFound[0] ||
    highTagsFound[0] ||
    (tags_all.length > 0 ? tags_all[0] : "none");

  // 5) Compute severity_normalized
  let severity_normalized: NormalizedSeverity;
  let reason: string;

  if (impact_level === "CRITICAL_IMPACT" && anomaly_score >= 5) {
    severity_normalized = "CRITICAL";
    reason = `${criticalTagsFound.join(",")} tag + score=${anomaly_score}`;
  } else if (impact_level === "CRITICAL_IMPACT" && anomaly_score < 5) {
    severity_normalized = "HIGH";
    reason = `${criticalTagsFound.join(",")} tag but low score=${anomaly_score}`;
  } else if (impact_level === "HIGH_IMPACT" && anomaly_score >= 10) {
    severity_normalized = "HIGH";
    reason = `${highTagsFound.join(",")} tag + score=${anomaly_score}`;
  } else if (impact_level === "HIGH_IMPACT" && anomaly_score >= 5) {
    severity_normalized = "MEDIUM";
    reason = `${highTagsFound.join(",")} tag + score=${anomaly_score}`;
  } else if (anomaly_score >= 10) {
    severity_normalized = "HIGH";
    reason = `anomaly score=${anomaly_score} (no critical/high tags)`;
  } else if (anomaly_score >= 5) {
    severity_normalized = "MEDIUM";
    reason = `anomaly score=${anomaly_score} (no critical/high tags)`;
  } else if (!hasMessages) {
    severity_normalized = "LOW";
    reason = "no messages present";
  } else {
    severity_normalized = "LOW";
    reason = `low anomaly score=${anomaly_score}, tag=${notableTag}`;
  }

  return {
    anomaly_score,
    tags_all,
    impact_level,
    confidence_level,
    severity_normalized,
    reason,
  };
}
