export type AnalyticsRange = "24h" | "7d" | "30d" | "3m";

export interface AnalyticsWindow {
  start: Date;
  end: Date;
  bucketCount: number;
  bucketSizeMs: number;
}

export interface AnalyticsAggregateRow {
  bucketIndex: number;
  attacks: number | bigint;
  blocked: number | bigint;
  critical: number | bigint;
  high: number | bigint;
  medium: number | bigint;
  low: number | bigint;
}

export interface LogAnalyticsResponse {
  range: AnalyticsRange;
  start: string;
  end: string;
  summary: {
    totalRequests: number;
    blockedAttacks: number;
    threatLevel: "Low" | "Medium" | "High" | "Critical";
  };
  series: Array<{
    timestamp: string;
    attacks: number;
    blocked: number;
    allowed: number;
  }>;
}

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const RANGE_CONFIG: Record<
  AnalyticsRange,
  { bucketCount: number; bucketSizeMs: number }
> = {
  "24h": { bucketCount: 24, bucketSizeMs: HOUR_MS },
  "7d": { bucketCount: 7, bucketSizeMs: DAY_MS },
  "30d": { bucketCount: 30, bucketSizeMs: DAY_MS },
  // `getAnalyticsWindow` replaces this size for 3m with thirteen equal
  // buckets spanning exactly three calendar months.
  "3m": { bucketCount: 13, bucketSizeMs: 7 * DAY_MS },
};

function subtractUtcMonths(date: Date, months: number): Date {
  const targetMonth = date.getUTCFullYear() * 12 + date.getUTCMonth() - months;
  const year = Math.floor(targetMonth / 12);
  const month = targetMonth - year * 12;
  const lastDayOfMonth = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();

  return new Date(
    Date.UTC(
      year,
      month,
      Math.min(date.getUTCDate(), lastDayOfMonth),
      date.getUTCHours(),
      date.getUTCMinutes(),
      date.getUTCSeconds(),
      date.getUTCMilliseconds()
    )
  );
}

export function parseAnalyticsRange(value: unknown): AnalyticsRange {
  return value === "7d" || value === "30d" || value === "3m"
    ? value
    : "24h";
}

export function getAnalyticsWindow(
  range: AnalyticsRange,
  now = new Date()
): AnalyticsWindow {
  const config = RANGE_CONFIG[range];
  const end = new Date(now);
  const start =
    range === "3m"
      ? subtractUtcMonths(end, 3)
      : new Date(end.getTime() - config.bucketCount * config.bucketSizeMs);
  const bucketSizeMs = (end.getTime() - start.getTime()) / config.bucketCount;

  return { start, end, bucketCount: config.bucketCount, bucketSizeMs };
}

export function calculateThreatLevel(counts: {
  total: number;
  critical: number;
  high: number;
  medium: number;
}): "Low" | "Medium" | "High" | "Critical" {
  if (counts.total === 0) return "Low";

  const criticalPercent = (counts.critical / counts.total) * 100;
  const highPercent = (counts.high / counts.total) * 100;
  const mediumPercent = (counts.medium / counts.total) * 100;

  if (
    criticalPercent > 10 ||
    (criticalPercent > 5 && highPercent > 20)
  ) {
    return "Critical";
  }
  if (highPercent > 15 || (highPercent > 10 && mediumPercent > 30)) {
    return "High";
  }
  if (mediumPercent > 25 || (highPercent > 5 && mediumPercent > 15)) {
    return "Medium";
  }
  return "Low";
}

function toCount(value: number | bigint): number {
  return typeof value === "bigint" ? Number(value) : value;
}

export function buildLogAnalyticsResponse(
  range: AnalyticsRange,
  window: AnalyticsWindow,
  rows: AnalyticsAggregateRow[]
): LogAnalyticsResponse {
  const series = Array.from({ length: window.bucketCount }, (_, index) => ({
    timestamp: new Date(
      window.start.getTime() + index * window.bucketSizeMs
    ).toISOString(),
    attacks: 0,
    blocked: 0,
    allowed: 0,
  }));

  const severityCounts = { critical: 0, high: 0, medium: 0 };

  for (const row of rows) {
    const index = Number(row.bucketIndex);
    if (!Number.isInteger(index) || index < 0 || index >= series.length) {
      continue;
    }

    const attacks = toCount(row.attacks);
    const blocked = toCount(row.blocked);
    series[index].attacks += attacks;
    series[index].blocked += blocked;
    series[index].allowed += Math.max(0, attacks - blocked);
    severityCounts.critical += toCount(row.critical);
    severityCounts.high += toCount(row.high);
    severityCounts.medium += toCount(row.medium);
  }

  const totalRequests = series.reduce((sum, point) => sum + point.attacks, 0);
  const blockedAttacks = series.reduce((sum, point) => sum + point.blocked, 0);

  return {
    range,
    start: window.start.toISOString(),
    end: window.end.toISOString(),
    summary: {
      totalRequests,
      blockedAttacks,
      threatLevel: calculateThreatLevel({
        total: totalRequests,
        ...severityCounts,
      }),
    },
    series,
  };
}
