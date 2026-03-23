import type { Log } from "@prisma/client";
import geoip from "geoip-lite";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function countryForIp(ip: string): string {
  if (!ip || ip === "N/A") return "Unknown";
  if (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.16.") ||
    ip.startsWith("127.")
  ) {
    return "Local Network";
  }
  const g = geoip.lookup(ip);
  if (!g) return "Unknown";
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(g.country) || g.country;
  } catch {
    return g.country;
  }
}

type SeverityBucket = "Critical" | "High" | "Medium" | "Low";

function bucketFromLog(log: Log): SeverityBucket {
  const sev = (log.severity || "").toUpperCase();
  if (sev === "CRITICAL") return "Critical";
  if (sev === "HIGH") return "High";
  if (sev === "MEDIUM") return "Medium";
  if (sev === "LOW") return "Low";
  const msg = `${log.rule || ""} ${log.message || ""}`.toLowerCase();
  if (
    msg.includes("sql injection") ||
    msg.includes("rce") ||
    msg.includes("remote code")
  ) {
    return "Critical";
  }
  if (msg.includes("xss") || msg.includes("cross-site scripting")) return "High";
  if (
    msg.includes("injection") ||
    msg.includes("traversal") ||
    msg.includes("file inclusion")
  ) {
    return "Medium";
  }
  return "Low";
}

export interface ReportStats {
  totalAttacks: number;
  attackTypes: Map<string, number>;
  topAttackers: Map<string, { ip: string; country: string; count: number }>;
  bySeverity: Record<SeverityBucket, number>;
  top5AttackTypes: [string, number][];
  top5Attackers: [string, { ip: string; country: string; count: number }][];
}

export function buildStats(logs: Log[]): ReportStats {
  const attackTypes = new Map<string, number>();
  const topAttackers = new Map<string, { ip: string; country: string; count: number }>();
  const bySeverity: Record<SeverityBucket, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };

  for (const log of logs) {
    const label = (log.rule || log.message || "Security event").trim() || "Security event";
    attackTypes.set(label, (attackTypes.get(label) || 0) + 1);

    const ip = log.clientIp || "N/A";
    const country = countryForIp(ip);
    const key = `${ip}|${country}`;
    const prev = topAttackers.get(key);
    if (prev) prev.count += 1;
    else topAttackers.set(key, { ip, country, count: 1 });

    bySeverity[bucketFromLog(log)] += 1;
  }

  const top5AttackTypes = [...attackTypes.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const top5Attackers = [...topAttackers.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5)
    .map(([k, v]) => [k, v] as [string, { ip: string; country: string; count: number }]);

  return {
    totalAttacks: logs.length,
    attackTypes,
    topAttackers,
    bySeverity,
    top5AttackTypes,
    top5Attackers,
  };
}

export interface BuildReportParams {
  domain: string;
  organizationName: string;
  logs: Log[];
  startDate: Date;
  endDate: Date;
  periodLabel: string;
  logoCid: string | null;
}

const FONT =
  "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif";

/** Full-width logo row — its own visual band above all text. */
function buildLogoRow(logoCid: string | null, domain: string): string {
  const logoInner = logoCid
    ? `<img src="cid:${logoCid}" alt="Zergaw Cloud" width="240" style="max-width:260px;width:100%;height:auto;display:block;margin:0 auto;border:0;outline:none;text-decoration:none;" />`
    : `<table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"><tr><td style="font-size:20px;font-weight:700;color:#1e3a5f;font-family:${FONT};">${escapeHtml(domain)}</td></tr></table>`;

  return `
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#f0f9ff;border-bottom:1px solid #bae6fd;">
  <tr>
    <td align="center" style="padding:36px 28px 32px 28px;">
      ${logoInner}
    </td>
  </tr>
</table>`;
}

/** Title + meta — separate from logo, no side-by-side crowding. */
function buildTitleSection(params: {
  periodLabel: string;
  domain: string;
  organizationName: string;
  startStr: string;
  endStr: string;
}): string {
  const { periodLabel, domain, organizationName, startStr, endStr } = params;
  return `
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#ffffff;">
  <tr>
    <td style="padding:28px 28px 8px 28px;">
      <span style="display:inline-block;background:#e0f2fe;color:#0369a1;font-size:11px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;padding:7px 14px;border-radius:999px;font-family:${FONT};">${escapeHtml(periodLabel)}</span>
    </td>
  </tr>
  <tr>
    <td style="padding:12px 28px 6px 28px;">
      <p style="margin:0;font-size:22px;line-height:1.3;color:#0f172a;font-weight:700;font-family:${FONT};">WAF security report</p>
    </td>
  </tr>
  <tr>
    <td style="padding:4px 28px 8px 28px;">
      <p style="margin:0;font-size:18px;font-weight:600;color:#2563eb;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;">${escapeHtml(domain)}</p>
    </td>
  </tr>
  <tr>
    <td style="padding:0 28px 20px 28px;">
      <p style="margin:0;font-size:15px;line-height:1.5;color:#64748b;font-family:${FONT};">${escapeHtml("Zergaw Cloud WAF Security Update")}</p>
      <p style="margin:10px 0 0 0;font-size:13px;line-height:1.5;color:#94a3b8;font-family:${FONT};">
        <strong style="color:#475569;font-weight:600;">${escapeHtml(organizationName)}</strong>
        &nbsp;·&nbsp;
        ${escapeHtml(startStr)} → ${escapeHtml(endStr)}
      </p>
    </td>
  </tr>
</table>`;
}

function buildSectionTitle(title: string): string {
  return `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
  <tr>
    <td style="padding:20px 28px 12px 28px;border-top:1px solid #f1f5f9;">
      <p style="margin:0;font-size:13px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;color:#64748b;font-family:${FONT};">${escapeHtml(title)}</p>
    </td>
  </tr>
</table>`;
}

function buildCardInner(html: string): string {
  return `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
  <tr>
    <td style="padding:0 28px 24px 28px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;">
        <tr>
          <td style="padding:20px 22px;font-family:${FONT};font-size:14px;line-height:1.55;color:#334155;">
            ${html}
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>`;
}

function buildFooter(): string {
  const d = new Date().toISOString().slice(0, 10);
  return `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;border-top:1px solid #e2e8f0;">
  <tr>
    <td align="center" style="padding:22px 28px;font-size:12px;color:#94a3b8;font-family:${FONT};line-height:1.6;">
      Generated ${escapeHtml(d)} · Zergaw Cloud
    </td>
  </tr>
</table>`;
}

/** Solid colors — better support than gradients in Gmail/Outlook. */
function severityCell(
  label: string,
  count: number,
  pct: number,
  bg: string
): string {
  return `
<td width="25%" valign="top" style="padding:4px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr>
      <td align="center" style="background-color:${bg};padding:14px 8px;color:#ffffff;font-family:${FONT};border-radius:10px;">
        <div style="font-size:10px;font-weight:700;letter-spacing:0.08em;">${label}</div>
        <div style="font-size:22px;font-weight:800;line-height:1.2;margin-top:6px;">${count}</div>
        <div style="font-size:11px;opacity:0.95;margin-top:4px;">${pct.toFixed(1)}%</div>
      </td>
    </tr>
  </table>
</td>`;
}

function wrapOuterShell(inner: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Zergaw WAF Report</title>
</head>
<body style="margin:0;padding:0;background:#e2e8f0;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#e2e8f0;">
    <tr>
      <td align="center" style="padding:24px 12px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:640px;margin:0 auto;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 10px 40px rgba(15,23,42,0.1);">
          ${inner}
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

export function buildSummaryReportHtml(params: BuildReportParams): string {
  const { domain, organizationName, logs, startDate, endDate, periodLabel, logoCid } = params;

  const startStr = startDate.toISOString().slice(0, 10);
  const endStr = endDate.toISOString().slice(0, 10);

  const logoRow = buildLogoRow(logoCid, domain);
  const titleSection = buildTitleSection({
    periodLabel,
    domain,
    organizationName,
    startStr,
    endStr,
  });

  if (logs.length === 0) {
    const emptyBody = `
${logoRow}
${titleSection}
${buildSectionTitle("Status")}
${buildCardInner(
  `<p style="margin:0;">No WAF security events were recorded for <strong>${escapeHtml(domain)}</strong> during this period.</p>`
)}
${buildFooter()}`;
    return wrapOuterShell(emptyBody);
  }

  const stats = buildStats(logs);
  const total = stats.totalAttacks || 1;
  const severityCounts = stats.bySeverity;

  const severityRow = `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
  <tr>
    ${severityCell(
      "CRITICAL",
      severityCounts.Critical,
      (severityCounts.Critical / total) * 100,
      "#dc2626"
    )}
    ${severityCell(
      "HIGH",
      severityCounts.High,
      (severityCounts.High / total) * 100,
      "#ea580c"
    )}
    ${severityCell(
      "MEDIUM",
      severityCounts.Medium,
      (severityCounts.Medium / total) * 100,
      "#ca8a04"
    )}
    ${severityCell(
      "LOW",
      severityCounts.Low,
      (severityCounts.Low / total) * 100,
      "#16a34a"
    )}
  </tr>
</table>`;

  let attackBars = "";
  for (const [msg, count] of stats.top5AttackTypes) {
    const pct = (count / total) * 100;
    const w = Math.min(100, Math.round(pct));
    attackBars += `
<div style="margin-bottom:14px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr>
      <td style="font-size:13px;color:#334155;padding-bottom:6px;font-family:${FONT};">
        <span style="word-break:break-word;">${escapeHtml(msg)}</span>
      </td>
      <td align="right" style="font-size:13px;font-weight:600;color:#64748b;white-space:nowrap;padding-left:8px;">${count} (${pct.toFixed(1)}%)</td>
    </tr>
  </table>
  <div style="height:8px;background:#e2e8f0;border-radius:6px;overflow:hidden;">
    <div style="height:100%;width:${w}%;background-color:#ea580c;border-radius:6px;"></div>
  </div>
</div>`;
  }

  const topAttackersRows = stats.top5Attackers
    .map(([, v]) => {
      const pct = (v.count / total) * 100;
      return `<tr>
<td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:13px;color:#0f172a;font-family:${FONT};">${escapeHtml(v.ip)}<br><span style="font-size:11px;color:#94a3b8;">${escapeHtml(v.country)}</span></td>
<td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:13px;font-weight:600;color:#334155;font-family:${FONT};">${v.count}</td>
<td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:13px;color:#64748b;font-family:${FONT};">${pct.toFixed(1)}%</td>
</tr>`;
    })
    .join("");

  const sorted = [...logs].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
  const recent = sorted.slice(0, 10);

  const recentRows = recent
    .map((log) => {
      const ts = new Date(log.timestamp);
      const dateStr = ts.toISOString().slice(0, 10);
      const timeStr = ts.toISOString().slice(11, 19);
      const ip = log.clientIp || "N/A";
      const country = countryForIp(ip);
      const reqLine = `${log.method || "GET"} ${log.requestUrl || "/"}`;
      const msg = (log.rule || log.message || "—").slice(0, 500);
      const status = log.action === "blocked" ? "BLOCKED" : "WARNING";
      const badgeBg = log.action === "blocked" ? "#dc2626" : "#d97706";
      return `<tr>
<td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;vertical-align:top;font-family:${FONT};">
  <span style="color:#0f172a;">${dateStr}</span><br><span style="color:#94a3b8;font-size:11px;">${timeStr}</span>
</td>
<td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;vertical-align:top;font-family:${FONT};">${escapeHtml(ip)}<br><span style="color:#94a3b8;font-size:11px;">${escapeHtml(country)}</span></td>
<td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;word-break:break-word;vertical-align:top;font-family:${FONT};color:#334155;">${escapeHtml(reqLine)}</td>
<td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;word-break:break-word;vertical-align:top;font-family:${FONT};color:#475569;">${escapeHtml(msg)}</td>
<td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;vertical-align:top;">
  <span style="display:inline-block;background:${badgeBg};color:#fff;font-size:10px;font-weight:700;letter-spacing:0.04em;padding:4px 10px;border-radius:999px;font-family:${FONT};">${status}</span>
</td>
</tr>`;
    })
    .join("");

  const overviewHtml = `
<p style="margin:0 0 12px 0;"><strong style="color:#0f172a;">Total events:</strong> ${stats.totalAttacks}</p>
<p style="margin:0 0 12px 0;"><strong style="color:#0f172a;">Unique rule hits:</strong> ${stats.attackTypes.size}</p>
<p style="margin:0 0 18px 0;"><strong style="color:#0f172a;">Unique source IPs:</strong> ${new Set(logs.map((l) => l.clientIp).filter(Boolean)).size}</p>
${severityRow}`;

  const overviewBlock = `${buildSectionTitle("Security overview")}${buildCardInner(overviewHtml)}`;
  const typesBlock = `${buildSectionTitle("Top attack types")}${buildCardInner(attackBars)}`;

  const attackersTable = `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
  <thead>
    <tr style="background:#f1f5f9;">
      <th align="left" style="padding:10px 12px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;color:#64748b;border-bottom:2px solid #e2e8f0;font-family:${FONT};">IP</th>
      <th align="left" style="padding:10px 12px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;color:#64748b;border-bottom:2px solid #e2e8f0;font-family:${FONT};">Events</th>
      <th align="left" style="padding:10px 12px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;color:#64748b;border-bottom:2px solid #e2e8f0;font-family:${FONT};">Share</th>
    </tr>
  </thead>
  <tbody>${topAttackersRows}</tbody>
</table>`;

  const recentTable = `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
  <thead>
    <tr style="background:#f1f5f9;">
      <th align="left" style="padding:10px 8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.03em;color:#64748b;border-bottom:2px solid #e2e8f0;font-family:${FONT};">When</th>
      <th align="left" style="padding:10px 8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.03em;color:#64748b;border-bottom:2px solid #e2e8f0;font-family:${FONT};">IP</th>
      <th align="left" style="padding:10px 8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.03em;color:#64748b;border-bottom:2px solid #e2e8f0;font-family:${FONT};">Request</th>
      <th align="left" style="padding:10px 8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.03em;color:#64748b;border-bottom:2px solid #e2e8f0;font-family:${FONT};">Rule</th>
      <th align="left" style="padding:10px 8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.03em;color:#64748b;border-bottom:2px solid #e2e8f0;font-family:${FONT};">Status</th>
    </tr>
  </thead>
  <tbody>${recentRows}</tbody>
</table>`;

  const attackersBlock = `${buildSectionTitle("Top attackers")}${buildCardInner(attackersTable)}`;
  const recentBlock = `${buildSectionTitle("Recent activity")}${buildCardInner(recentTable)}`;

  const full = `
${logoRow}
${titleSection}
${overviewBlock}
${typesBlock}
${attackersBlock}
${recentBlock}
${buildFooter()}`;

  return wrapOuterShell(full);
}
