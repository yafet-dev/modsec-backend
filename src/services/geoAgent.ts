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
  domain: string;
  mode: string;
  allow: string[];
  deny: string[];
  /**
   * Whether an nginx server block for this domain actually includes the rule.
   * Rule files can exist on disk with no vhost referencing them, in which case
   * nothing is enforced -- so this is checked rather than assumed.
   * Optional for compatibility with an agent that predates the field.
   */
  enforced?: boolean;
  enforced_in?: string[];
}

interface GeoAgentAllStatusResponse {
  domains: GeoAgentStatusResponse[];
  total_domains: number;
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
  async setMode(
    domain: string,
    mode: "allow_only" | "deny_only",
    force: boolean = false
  ): Promise<GeoAgentModeResponse> {
    return this.agentFetch<GeoAgentModeResponse>(
      `/v1/geo/${encodeURIComponent(domain)}/mode`,
      {
        method: "POST",
        body: JSON.stringify({ mode, force }),
        includeJson: true,
      }
    );
  }

  /**
   * Add a country to a domain's allow list
   */
  async addAllowCountry(
    domain: string,
    country: string
  ): Promise<GeoAgentCountryResponse> {
    return this.agentFetch<GeoAgentCountryResponse>(
      `/v1/geo/${encodeURIComponent(domain)}/allow`,
      {
        method: "POST",
        body: JSON.stringify({ country }),
        includeJson: true,
      }
    );
  }

  /**
   * Remove a country from a domain's allow list
   */
  async removeAllowCountry(
    domain: string,
    country: string,
    force: boolean = false
  ): Promise<GeoAgentCountryResponse> {
    return this.agentFetch<GeoAgentCountryResponse>(
      `/v1/geo/${encodeURIComponent(domain)}/allow/${encodeURIComponent(country)}?force=${force}`,
      { method: "DELETE", includeJson: false }
    );
  }

  /**
   * Add a country to a domain's deny list
   */
  async addDenyCountry(
    domain: string,
    country: string
  ): Promise<GeoAgentCountryResponse> {
    return this.agentFetch<GeoAgentCountryResponse>(
      `/v1/geo/${encodeURIComponent(domain)}/deny`,
      {
        method: "POST",
        body: JSON.stringify({ country }),
        includeJson: true,
      }
    );
  }

  /**
   * Remove a country from a domain's deny list
   */
  async removeDenyCountry(
    domain: string,
    country: string
  ): Promise<GeoAgentCountryResponse> {
    return this.agentFetch<GeoAgentCountryResponse>(
      `/v1/geo/${encodeURIComponent(domain)}/deny/${encodeURIComponent(country)}`,
      { method: "DELETE", includeJson: false }
    );
  }

  /**
   * Get a single domain's geo status from the agent.
   *
   * A domain the agent has never seen reports mode "unknown" with empty lists
   * rather than erroring, so this is safe to call before anything is configured.
   */
  async getStatus(domain: string): Promise<GeoAgentStatusResponse> {
    return this.agentFetch<GeoAgentStatusResponse>(
      `/v1/geo/${encodeURIComponent(domain)}/status`,
      { method: "GET", includeJson: false }
    );
  }

  /**
   * Get geo status for every domain the agent has configured.
   */
  async getAllStatus(): Promise<GeoAgentAllStatusResponse> {
    return this.agentFetch<GeoAgentAllStatusResponse>("/v1/geo/status", {
      method: "GET",
      includeJson: false,
    });
  }

  /**
   * Sync one domain's geo access settings to the agent.
   *
   * Sets the mode and reconciles both country lists. The agent provisions the
   * domain's nginx files on the first call, so a domain that has never had geo
   * settings before works without any manual setup.
   */
  async syncSettings(
    domain: string,
    mode: "allow-all" | "allow-only" | "ban-specific",
    allowedCountries: string[],
    deniedCountries: string[]
  ): Promise<void> {
    if (!domain || !domain.trim()) {
      throw new Error("A domain is required to sync geo access settings.");
    }

    const target = domain.trim().toLowerCase();
    const currentStatus = await this.getStatus(target);

    /** Bring a list to exactly `desired`, removing extras and adding the rest. */
    const reconcile = async (
      current: string[],
      desired: string[],
      add: (country: string) => Promise<unknown>,
      remove: (country: string) => Promise<unknown>
    ): Promise<void> => {
      const currentSet = new Set(current);
      const desiredSet = new Set(desired);

      for (const country of currentSet) {
        if (!desiredSet.has(country)) await remove(country);
      }
      for (const country of desiredSet) {
        if (!currentSet.has(country)) await add(country);
      }
    };

    const clearAllow = () =>
      reconcile(
        currentStatus.allow,
        [],
        (c) => this.addAllowCountry(target, c),
        (c) => this.removeAllowCountry(target, c, true)
      );

    const clearDeny = () =>
      reconcile(
        currentStatus.deny,
        [],
        (c) => this.addDenyCountry(target, c),
        (c) => this.removeDenyCountry(target, c)
      );

    if (mode === "allow-all") {
      // deny_only with an empty deny list blocks nobody.
      await clearDeny();
      await clearAllow();
      await this.setMode(target, "deny_only", true);
    } else if (mode === "allow-only") {
      // Lists first, then the mode, so the agent never sits in allow_only with
      // an empty allow list -- which would block every visitor.
      await clearDeny();
      await reconcile(
        currentStatus.allow,
        allowedCountries,
        (c) => this.addAllowCountry(target, c),
        (c) => this.removeAllowCountry(target, c, true)
      );
      await this.setMode(target, "allow_only", allowedCountries.length === 0);
    } else if (mode === "ban-specific") {
      await clearAllow();
      await reconcile(
        currentStatus.deny,
        deniedCountries,
        (c) => this.addDenyCountry(target, c),
        (c) => this.removeDenyCountry(target, c)
      );
      await this.setMode(target, "deny_only", true);
    } else {
      throw new Error(`Unknown geo access mode: ${mode}`);
    }

    await this.assertEnforced(target);
  }

  /**
   * Confirm nginx is actually enforcing the rules before we call this a
   * success.
   *
   * The agent already refuses when it cannot find a server block, but this
   * verifies the end state rather than trusting the sequence of writes. It is
   * the difference between "we wrote some files" and "the control is live" --
   * a distinction that previously cost a silently-unprotected domain.
   */
  private async assertEnforced(domain: string): Promise<void> {
    const status = await this.getStatus(domain);

    // An older agent does not report the field; nothing to verify against.
    if (status.enforced === undefined) return;

    if (!status.enforced) {
      throw new Error(
        `Geo rules for '${domain}' were written but no nginx server block ` +
          `includes them, so nothing is enforced. Check that a server block ` +
          `declares 'server_name ${domain};'.`
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
