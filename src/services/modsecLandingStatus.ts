import { prisma } from "../lib/prisma";
import {
  type PendingLandingSnapshot,
  scanPendingLandingRows,
} from "./modsecLandingSummary";

const PENDING_LANDING_PAGE_SIZE = 500;
const PENDING_LANDING_CACHE_TTL_MS = 5_000;

let cachedSnapshot:
  | { snapshot: PendingLandingSnapshot; expiresAt: number }
  | undefined;
let inFlightSnapshot: Promise<PendingLandingSnapshot> | undefined;

async function loadPendingLandingSnapshot(): Promise<PendingLandingSnapshot> {
  return scanPendingLandingRows(
    async (afterId, take) =>
      prisma.modsecLanding.findMany({
        where: {
          processed: false,
          ...(afterId === undefined ? {} : { id: { gt: afterId } }),
        },
        orderBy: { id: "asc" },
        take,
        select: {
          id: true,
          time: true,
          data: true,
          processed: true,
        },
      }),
    { pageSize: PENDING_LANDING_PAGE_SIZE }
  );
}

/**
 * Share one short-lived global queue snapshot. Tenant filtering happens only
 * after this internal value is returned and raw landing payloads never leave
 * the backend.
 */
export async function getCachedPendingLandingSnapshot(): Promise<PendingLandingSnapshot> {
  const now = Date.now();
  if (cachedSnapshot && cachedSnapshot.expiresAt > now) {
    return cachedSnapshot.snapshot;
  }

  if (!inFlightSnapshot) {
    inFlightSnapshot = loadPendingLandingSnapshot();
    const pending = inFlightSnapshot;
    const clearPending = () => {
      if (inFlightSnapshot === pending) inFlightSnapshot = undefined;
    };
    pending.then(clearPending, clearPending);
  }

  const snapshot = await inFlightSnapshot;
  cachedSnapshot = {
    snapshot,
    expiresAt: Date.now() + PENDING_LANDING_CACHE_TTL_MS,
  };
  return snapshot;
}
