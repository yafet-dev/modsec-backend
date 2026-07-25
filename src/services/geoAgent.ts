import {
  normalizeEnvValue,
  resolveAgentEndpoint,
  type AgentEndpoint,
} from "../utils/agentEndpoint";

/**
 * Geo Agent Service
 * Handles communication with the Geo Agent to manage geo access control.
 *
 * Credential policy
 * -----------------
 * Mirrors the WAF agent: when the agent URL resolves to localhost or a private
 * network address, the bearer token is OPTIONAL because the request never
 * leaves the trusted network. When it points at a public IP or domain, the
 * token is REQUIRED and calls fail fast instead of going out unauthenticated.
 *
 * The geo endpoints are not signature-protected on the agent side, so unlike
 * the WAF toggle there is no private key involved here.
 */

const DEFAULT_AGENT_URL = "http://localhost:8080";

interface GeoAgentConfig {
  endpoint: AgentEndpoint;
  authToken: string;
}

interface GeoAgentModeResponse {
  ok: boolean;
  mode?: string;
  error?: string;
}

interface GeoAgentCountryResponse {
  ok: boolean;
  added?: string;
  removed?: string;
  message?: string;
  error?: string;
}

interface GeoAgentStatusResponse {
  mode: string;
  allow: string[];
  deny: string[];
}

class GeoAgentService {
  private config: GeoAgentConfig;

  constructor() {
    // Default to WAF_AGENT_URL (port 8080) since the geo endpoints now live in
    // the same service.
    const endpoint = resolveAgentEndpoint(
      normalizeEnvValue(process.env.GEO_AGENT_URL) ||
        normalizeEnvValue(process.env.WAF_AGENT_URL),
      DEFAULT_AGENT_URL
    );

    this.config = {
      endpoint,
      authToken:
        normalizeEnvValue(process.env.GEO_AGENT_AUTH_TOKEN) ||
        normalizeEnvValue(process.env.WAF_AGENT_AUTH_TOKEN),
    };

    this.logConfiguration();
  }

  /** True when the agent sits outside the trusted network. */
  private get credentialsRequired(): boolean {
    return !this.config.endpoint.isLocal;
  }

  /** Report the credential posture once at startup. */
  private logConfiguration(): void {
    const { endpoint } = this.config;

    if (!this.credentialsRequired) {
      console.log(
        `🔓 Geo Agent at ${endpoint.url} is local (${endpoint.reason}). Auth token is optional.`
      );
      return;
    }

    if (!this.config.authToken) {
      console.warn(
        `⚠️  Geo Agent at ${endpoint.url} is remote (${endpoint.reason}) but ` +
          "GEO_AGENT_AUTH_TOKEN / WAF_AGENT_AUTH_TOKEN is missing. Geo agent calls will fail until configured."
      );
      return;
    }

    console.log(
      `🔒 Geo Agent at ${endpoint.url} is remote (${endpoint.reason}). Requests are authenticated.`
    );
  }

  /**
   * Block the call when a remote agent is configured without a token.
   * Local agents always pass.
   */
  private assertCredentialsConfigured(): void {
    if (!this.credentialsRequired || this.config.authToken) return;

    throw new Error(
      `Geo agent at ${this.config.endpoint.url} is remote (${this.config.endpoint.reason}), ` +
        "so GEO_AGENT_AUTH_TOKEN (or WAF_AGENT_AUTH_TOKEN) must be set in .env. " +
        "The token is only optional when the agent runs on localhost or a private network address."
    );
  }

  /** Authorization header, present only when a token is configured. */
  private buildHeaders(includeJson: boolean): Record<string, string> {
    const headers: Record<string, string> = {};
    if (includeJson) headers["Content-Type"] = "application/json";
    if (this.config.authToken) {
      headers.Authorization = `Bearer ${this.config.authToken}`;
    }
    return headers;
  }

  /**
   * Issue a request to the agent and decode the JSON response.
   * Wraps transport failures with the target URL so an unreachable agent is
   * identifiable from the error alone.
   */
  private async agentFetch<T>(
    path: string,
    init: { method: string; body?: string; includeJson: boolean }
  ): Promise<T> {
    this.assertCredentialsConfigured();

    const target = `${this.config.endpoint.url}${path}`;

    let response: Response;
    try {
      response = await fetch(target, {
        method: init.method,
        headers: this.buildHeaders(init.includeJson),
        body: init.body,
      });
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Unknown error";
      throw new Error(
        `Could not reach Geo agent at ${target}: ${detail}. ` +
          "Check that the agent is running and that GEO_AGENT_URL / WAF_AGENT_URL is correct."
      );
    }

    if (!response.ok) {
      const errorBody = await response.text().catch(() => "");
      const hint =
        response.status === 401 || response.status === 403
          ? " (the agent rejected the credentials — check GEO_AGENT_AUTH_TOKEN)"
          : "";
      throw new Error(
        `Geo Agent returned ${response.status}: ${errorBody || response.statusText}${hint}`
      );
    }

    return (await response.json()) as T;
  }

  /**
   * Configuration snapshot for diagnostics. Reports whether a token is
   * present, never what it is.
   */
  getStatusInfo(): {
    url: string;
    hostname: string;
    isLocal: boolean;
    reason: string;
    credentialsRequired: boolean;
    hasAuthToken: boolean;
    ready: boolean;
  } {
    const { endpoint } = this.config;
    const hasAuthToken = this.config.authToken.length > 0;

    return {
      url: endpoint.url,
      hostname: endpoint.hostname,
      isLocal: endpoint.isLocal,
      reason: endpoint.reason,
      credentialsRequired: this.credentialsRequired,
      hasAuthToken,
      ready: !this.credentialsRequired || hasAuthToken,
    };
  }

  /**
   * Set the geo access mode (allow_only or deny_only)
   */
  async setMode(mode: "allow_only" | "deny_only", force: boolean = false): Promise<GeoAgentModeResponse> {
    return this.agentFetch<GeoAgentModeResponse>("/v1/geo/mode", {
      method: "POST",
      body: JSON.stringify({ mode, force }),
      includeJson: true,
    });
  }

  /**
   * Add a country to the allow list
   */
  async addAllowCountry(country: string): Promise<GeoAgentCountryResponse> {
    return this.agentFetch<GeoAgentCountryResponse>("/v1/geo/allow", {
      method: "POST",
      body: JSON.stringify({ country }),
      includeJson: true,
    });
  }

  /**
   * Remove a country from the allow list
   */
  async removeAllowCountry(country: string, force: boolean = false): Promise<GeoAgentCountryResponse> {
    return this.agentFetch<GeoAgentCountryResponse>(
      `/v1/geo/allow/${encodeURIComponent(country)}?force=${force}`,
      { method: "DELETE", includeJson: false }
    );
  }

  /**
   * Add a country to the deny list
   */
  async addDenyCountry(country: string): Promise<GeoAgentCountryResponse> {
    return this.agentFetch<GeoAgentCountryResponse>("/v1/geo/deny", {
      method: "POST",
      body: JSON.stringify({ country }),
      includeJson: true,
    });
  }

  /**
   * Remove a country from the deny list
   */
  async removeDenyCountry(country: string): Promise<GeoAgentCountryResponse> {
    return this.agentFetch<GeoAgentCountryResponse>(
      `/v1/geo/deny/${encodeURIComponent(country)}`,
      { method: "DELETE", includeJson: false }
    );
  }

  /**
   * Get current geo access status from agent
   */
  async getStatus(): Promise<GeoAgentStatusResponse> {
    return this.agentFetch<GeoAgentStatusResponse>("/v1/geo/status", {
      method: "GET",
      includeJson: false,
    });
  }

  /**
   * Sync geo access settings to the agent
   * This is a high-level method that sets mode and syncs all countries
   */
  async syncSettings(
    mode: "allow-all" | "allow-only" | "ban-specific",
    allowedCountries: string[],
    deniedCountries: string[]
  ): Promise<void> {
    try {
      // Get current status from agent
      const currentStatus = await this.getStatus();

      // Determine agent mode based on backend mode
      if (mode === "allow-all") {
        // For allow-all: set to deny_only with empty deny list (effectively allows all)
        // First, clear all deny countries
        for (const country of currentStatus.deny) {
          await this.removeDenyCountry(country);
        }
        
        // Clear all allow countries (shouldn't be any in deny_only mode, but just in case)
        for (const country of currentStatus.allow) {
          await this.removeAllowCountry(country, true);
        }
        
        // Set mode to deny_only (with empty deny list = allows all)
        await this.setMode("deny_only", true);
      } else if (mode === "allow-only") {
        // For allow-only: sync lists first, then set mode
        
        // Clear all deny countries first (they shouldn't exist in allow_only mode)
        for (const country of currentStatus.deny) {
          await this.removeDenyCountry(country);
        }

        // Sync allow list: remove countries not in new list, add countries not in current list
        const currentAllowSet = new Set(currentStatus.allow);
        const newAllowSet = new Set(allowedCountries);

        // Remove countries that are no longer allowed
        for (const country of currentAllowSet) {
          if (!newAllowSet.has(country)) {
            await this.removeAllowCountry(country, true);
          }
        }

        // Add new allowed countries
        for (const country of allowedCountries) {
          if (!currentAllowSet.has(country)) {
            await this.addAllowCountry(country);
          }
        }

        // Set mode to allow_only (use force=true if list is empty, though backend should prevent this)
        await this.setMode("allow_only", allowedCountries.length === 0);
      } else if (mode === "ban-specific") {
        // For ban-specific: sync lists first, then set mode
        
        // Clear all allow countries first (they shouldn't exist in deny_only mode)
        for (const country of currentStatus.allow) {
          await this.removeAllowCountry(country, true);
        }

        // Sync deny list: remove countries not in new list, add countries not in current list
        const currentDenySet = new Set(currentStatus.deny);
        const newDenySet = new Set(deniedCountries);

        // Remove countries that are no longer denied
        for (const country of currentDenySet) {
          if (!newDenySet.has(country)) {
            await this.removeDenyCountry(country);
          }
        }

        // Add new denied countries
        for (const country of deniedCountries) {
          if (!currentDenySet.has(country)) {
            await this.addDenyCountry(country);
          }
        }

        // Set mode to deny_only
        await this.setMode("deny_only", true);
      }
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to sync settings with Geo agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Check if agent is available
   */
  async checkHealth(): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.endpoint.url}/health`, {
        method: "GET",
        signal: AbortSignal.timeout(5000),
      });

      return response.ok;
    } catch {
      return false;
    }
  }
}

// Export singleton instance
let geoAgentService: GeoAgentService;
try {
  geoAgentService = new GeoAgentService();
} catch (error) {
  console.error("❌ Failed to initialize Geo Agent Service:", error);
  console.error("   Server will continue but Geo agent calls will fail.");
  // Create a dummy service that will throw errors when used
  geoAgentService = new GeoAgentService();
}

export { geoAgentService };
