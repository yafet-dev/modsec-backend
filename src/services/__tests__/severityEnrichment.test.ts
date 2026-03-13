/**
 * Unit tests for severityEnrichment
 *
 * Run:  npm run test:severity
 *       (or)  npx tsx src/services/__tests__/severityEnrichment.test.ts
 */

import { enrichSeverity, type ModsecMessageInput } from "../severityEnrichment";

let passed = 0;
let failed = 0;

function assert(
  condition: boolean,
  testName: string,
  details?: string
): void {
  if (condition) {
    console.log(`  ✅ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${testName}${details ? " — " + details : ""}`);
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Helper: build a messages array with optional anomaly-score message and tags
// ---------------------------------------------------------------------------
function makeMessages(opts: {
  tags?: string[];
  anomalyScore?: number;
  ruleMessage?: string;
}): ModsecMessageInput[] {
  const msgs: ModsecMessageInput[] = [];

  // Primary rule message
  if (opts.ruleMessage || opts.tags) {
    msgs.push({
      message: opts.ruleMessage || "Some rule triggered",
      details: {
        ruleId: "100001",
        tags: opts.tags || [],
      },
    });
  }

  // Anomaly score summary message (if any)
  if (opts.anomalyScore !== undefined && opts.anomalyScore > 0) {
    msgs.push({
      message: `Inbound Anomaly Score Exceeded (Total Score: ${opts.anomalyScore})`,
      details: {
        ruleId: "949110",
        tags: ["anomaly-evaluation"],
      },
    });
  }

  return msgs;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
console.log("\n🧪 Running severity enrichment tests...\n");

// (a) XSS score 20 => HIGH
(function testXssScore20() {
  const msgs = makeMessages({
    tags: ["attack-xss", "OWASP_CRS"],
    anomalyScore: 20,
    ruleMessage: "XSS Attack Detected",
  });
  const result = enrichSeverity(msgs);
  assert(
    result.severity_normalized === "HIGH",
    "XSS score=20 => HIGH",
    `got ${result.severity_normalized}, reason: ${result.reason}`
  );
  assert(result.anomaly_score === 20, "anomaly_score is 20");
  assert(result.impact_level === "HIGH_IMPACT", "impact_level is HIGH_IMPACT");
  assert(
    result.confidence_level === "VERY_HIGH_CONF",
    "confidence_level is VERY_HIGH_CONF"
  );
})();

// (b) RCE + LFI score 10 => CRITICAL
(function testRceLfiScore10() {
  const msgs = makeMessages({
    tags: ["attack-rce", "attack-lfi", "OWASP_CRS"],
    anomalyScore: 10,
    ruleMessage: "Remote Code Execution attempt",
  });
  const result = enrichSeverity(msgs);
  assert(
    result.severity_normalized === "CRITICAL",
    "RCE/LFI score=10 => CRITICAL",
    `got ${result.severity_normalized}, reason: ${result.reason}`
  );
  assert(result.anomaly_score === 10, "anomaly_score is 10");
  assert(
    result.impact_level === "CRITICAL_IMPACT",
    "impact_level is CRITICAL_IMPACT"
  );
  assert(
    result.confidence_level === "HIGH_CONF",
    "confidence_level is HIGH_CONF"
  );
})();

// (c) RCE score 3 => HIGH (critical tag but low confidence)
(function testRceScore3() {
  const msgs = makeMessages({
    tags: ["attack-rce"],
    anomalyScore: 3,
    ruleMessage: "RCE attempt detected",
  });
  const result = enrichSeverity(msgs);
  assert(
    result.severity_normalized === "HIGH",
    "RCE score=3 => HIGH",
    `got ${result.severity_normalized}, reason: ${result.reason}`
  );
  assert(result.anomaly_score === 3, "anomaly_score is 3");
  assert(
    result.impact_level === "CRITICAL_IMPACT",
    "impact_level is CRITICAL_IMPACT"
  );
  assert(result.confidence_level === "LOW_CONF", "confidence_level is LOW_CONF");
})();

// (d) No messages => LOW
(function testNoMessages() {
  const result = enrichSeverity(undefined);
  assert(
    result.severity_normalized === "LOW",
    "No messages => LOW",
    `got ${result.severity_normalized}, reason: ${result.reason}`
  );
  assert(result.anomaly_score === 0, "anomaly_score is 0");
  assert(result.impact_level === "LOW_IMPACT", "impact_level is LOW_IMPACT");
  assert(result.tags_all.length === 0, "tags_all is empty");

  // Also test with null
  const result2 = enrichSeverity(null);
  assert(result2.severity_normalized === "LOW", "null messages => LOW");

  // Also test with empty array
  const result3 = enrichSeverity([]);
  assert(result3.severity_normalized === "LOW", "empty messages => LOW");
})();

// (e) Messages exist but no anomaly score message => LOW (score=0)
(function testMessagesNoScore() {
  const msgs: ModsecMessageInput[] = [
    {
      message: "Request body no files data length is larger than the configured limit",
      details: {
        ruleId: "200002",
        tags: ["paranoia-level/1"],
      },
    },
  ];
  const result = enrichSeverity(msgs);
  assert(
    result.severity_normalized === "LOW",
    "Messages but no anomaly score => LOW",
    `got ${result.severity_normalized}, reason: ${result.reason}`
  );
  assert(result.anomaly_score === 0, "anomaly_score is 0");
  assert(
    result.impact_level === "MEDIUM_IMPACT",
    "impact_level is MEDIUM_IMPACT (has messages, no attack tags)"
  );
})();

// (f) Random attack with score 8 => MEDIUM
(function testRandomAttackScore8() {
  const msgs = makeMessages({
    tags: ["paranoia-level/1", "language-shell"],
    anomalyScore: 8,
    ruleMessage: "Some generic rule match",
  });
  const result = enrichSeverity(msgs);
  assert(
    result.severity_normalized === "MEDIUM",
    "Random attack score=8 => MEDIUM",
    `got ${result.severity_normalized}, reason: ${result.reason}`
  );
  assert(result.anomaly_score === 8, "anomaly_score is 8");
  assert(
    result.impact_level === "MEDIUM_IMPACT",
    "impact_level is MEDIUM_IMPACT (no critical/high tags)"
  );
  assert(
    result.confidence_level === "MEDIUM_CONF",
    "confidence_level is MEDIUM_CONF"
  );
})();

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\n📊 Results: ${passed} passed, ${failed} failed\n`);
if (failed > 0) {
  process.exit(1);
}
