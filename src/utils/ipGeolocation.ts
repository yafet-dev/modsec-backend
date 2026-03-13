import { PRIVATE_IP_RANGES, LOCALHOST_IPS } from "../constants/ipRanges";

export interface IPLocation {
  country: string;
  countryCode?: string;
  lat: number;
  lng: number;
}

// Cache to avoid hitting API rate limits
const locationCache = new Map<string, CacheEntry>();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours cache

interface CacheEntry {
  location: IPLocation;
  timestamp: number;
}

/**
 * Check if an IP address is a private/local IP address
 */
export function isPrivateIP(ip: string): boolean {
  // Check for localhost IPs
  if (LOCALHOST_IPS.includes(ip as any)) {
    return true;
  }

  // Check for private IP ranges
  if (ip.startsWith(PRIVATE_IP_RANGES.PRIVATE_CLASS_C)) {
    return true;
  }

  if (ip.startsWith(PRIVATE_IP_RANGES.PRIVATE_CLASS_A)) {
    return true;
  }

  // Check for private Class B range (172.16.0.0/12)
  for (const prefix of PRIVATE_IP_RANGES.PRIVATE_CLASS_B) {
    if (ip.startsWith(prefix)) {
      return true;
    }
  }

  return false;
}

/**
 * Get country and coordinates from IP address using ip-api.com (free API)
 * Returns location information including country name, latitude, and longitude
 * 
 * Free tier: 45 requests/minute, no API key required
 */
export async function getLocationFromIP(ip: string): Promise<IPLocation> {
  // Handle private/local IPs
  if (isPrivateIP(ip)) {
    return { country: "Local", lat: 0, lng: 0 };
  }

  // Check cache first
  const cached = locationCache.get(ip);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.location;
  }

  try {
    // Use ip-api.com free API (no API key required)
    // Format: http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,lat,lon
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

    try {
      const response = await fetch(
        `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,lat,lon`,
        {
          method: "GET",
          headers: {
            "Accept": "application/json",
          },
          signal: controller.signal,
        }
      );

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`API returned status ${response.status}`);
      }

      const data = await response.json() as { status?: string; message?: string; country?: string; countryCode?: string; lat?: number; lon?: number };

      // Check if API returned an error
      if (data.status === "fail") {
        const fallback: IPLocation = { country: "Unknown", lat: 20, lng: 0 };
        // Cache the fallback to avoid repeated failed requests (shorter cache for failures)
        locationCache.set(ip, { location: fallback, timestamp: Date.now() });
        return fallback;
      }

      // Extract country name, country code, and coordinates
      const country = data.country || "Unknown";
      const countryCode = data.countryCode || undefined;
      const lat = data.lat || 20;
      const lng = data.lon || 0; // Note: API returns "lon" not "lng"

      const location: IPLocation = {
        country: country,
        countryCode: countryCode,
        lat: lat,
        lng: lng,
      };

      // Cache the result
      locationCache.set(ip, { location, timestamp: Date.now() });

      return location;
    } catch (fetchError) {
      clearTimeout(timeoutId);
      throw fetchError;
    }
  } catch (error) {
    // Only log non-timeout errors to reduce log spam
    if (error instanceof Error && error.name !== "AbortError" && !error.message.includes("timeout")) {
      console.error(`[IP Geolocation] Error fetching location for IP ${ip}:`, error);
    }
    // Return fallback location
    const fallback: IPLocation = { country: "Unknown", lat: 20, lng: 0 };
    // Cache the fallback to avoid repeated failed requests (shorter cache for failures - 1 hour)
    const failureCacheTTL = 60 * 60 * 1000; // 1 hour for failures
    locationCache.set(ip, { location: fallback, timestamp: Date.now() - (CACHE_TTL - failureCacheTTL) });
    return fallback;
  }
}

/**
 * Batch get locations for multiple IPs (with rate limiting)
 * Processes IPs in batches to respect API rate limits (45 requests/minute)
 */
export async function getLocationsFromIPs(ips: string[]): Promise<Map<string, IPLocation>> {
  const results = new Map<string, IPLocation>();
  const uniqueIPs = Array.from(new Set(ips)); // Remove duplicates
  const uncachedIPs: string[] = [];

  // Check cache for all IPs first
  for (const ip of uniqueIPs) {
    if (isPrivateIP(ip)) {
      results.set(ip, { country: "Local", lat: 0, lng: 0 });
      continue;
    }

    const cached = locationCache.get(ip);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      results.set(ip, cached.location);
    } else {
      uncachedIPs.push(ip);
    }
  }

  // Process uncached IPs in smaller batches with delays to respect rate limits
  // ip-api.com free tier: 45 requests/minute = ~0.75 requests/second
  // We'll process 3 at a time with 2 second delays between batches to stay under limit
  const BATCH_SIZE = 3;
  const BATCH_DELAY = 2000; // 2 seconds between batches
  
  for (let i = 0; i < uncachedIPs.length; i += BATCH_SIZE) {
    const batch = uncachedIPs.slice(i, i + BATCH_SIZE);
    
    // Process batch in parallel (small batch size prevents overwhelming API)
    const batchPromises = batch.map(async (ip) => {
      try {
        const location = await getLocationFromIP(ip);
        results.set(ip, location);
      } catch (error) {
        // Individual request failures are already handled in getLocationFromIP
        results.set(ip, { country: "Unknown", lat: 20, lng: 0 });
      }
    });

    await Promise.all(batchPromises);

    // Add delay between batches to respect rate limit (except after last batch)
    if (i + BATCH_SIZE < uncachedIPs.length) {
      await new Promise(resolve => setTimeout(resolve, BATCH_DELAY));
    }
  }

  return results;
}
