import crypto from "crypto";
import {
  normalizeEnvValue,
  resolveAgentEndpoint,
  type AgentEndpoint,
} from "../utils/agentEndpoint";

/**
 * WAF Agent Service
 * Handles communication with the WAF agent to toggle ModSecurity on/off,
 * and to ban/unban IP addresses.
 *
 * Communication flow (matches test_toggle.sh):
 * 1. Backend has PRIVATE key (to sign requests)
 * 2. Agent has PUBLIC key (to verify signatures)
 * 3. Data format: "domain|enabled" where enabled is lowercase "true" or "false"
 * 4. Uses RSA PSS padding with SHA256
 *
 * Credential policy
 * -----------------
 * Signing keys and bearer tokens exist to protect requests that cross an
 * untrusted network. When the agent runs locally — loopback, an RFC1918
 * address, a Docker service name — nothing leaves the trusted network, so both
 * credentials are OPTIONAL and the service talks to the agent unauthenticated.
 *
 * When WAF_AGENT_URL points at a public IP or public domain, both the private
 * key and the auth token are REQUIRED and calls fail fast with an explicit
 * error rather than silently sending unsigned requests over the internet.
 *
 * Credentials are always used when present, local or not, so an existing
 * fully-configured deployment behaves exactly as before.
 *
 * There is no flag to bypass this. A tunnelled agent (WireGuard, Tailscale, an
 * SSH forward) is reached at its private address and already counts as local;
 * the only thing a bypass could buy is an unauthenticated public agent.
 */

const DEFAULT_AGENT_URL = "http://localhost:8080";

interface WAFAgentConfig {
  endpoint: AgentEndpoint;
  privateKey: string;
  authToken: string;
}

interface ToggleWAFRequest {
  domain: string;
  enabled: boolean;
  /** Omitted when talking to a local agent with no signing key configured. */
  signature?: string;
}

interface ToggleWAFResponse {
  status: string;
  message: string;
  domain: string;
  modsecurity_status: string;
}

/** Diagnostic snapshot of how the service is configured, safe to log or serve. */
export interface WAFAgentStatusInfo {
  url: string;
  hostname: string;
  isLocal: boolean;
  reason: string;
  credentialsRequired: boolean;
  hasPrivateKey: boolean;
  hasAuthToken: boolean;
  ready: boolean;
  missing: string[];
}

class WAFAgentService {
  private config: WAFAgentConfig;
  private privateKeyObject: crypto.KeyObject | null = null;

  constructor() {
    const endpoint = resolveAgentEndpoint(
      process.env.WAF_AGENT_URL,
      DEFAULT_AGENT_URL
    );

    this.config = {
      endpoint,
      privateKey: normalizeEnvValue(process.env.WAF_AGENT_PRIVATE_KEY),
      authToken: normalizeEnvValue(process.env.WAF_AGENT_AUTH_TOKEN),
    };

    this.loadPrivateKey();
    this.logConfiguration();
  }

  /** True when the agent sits outside the trusted network. */
  private get credentialsRequired(): boolean {
    return !this.config.endpoint.isLocal;
  }

  /**
   * Load the private key from the environment variable.
   * The key should be in PEM format (can include newlines, headers, etc.).
   * Never throws: a missing or invalid key must not stop the server from
   * booting, it only blocks WAF agent calls that actually need a signature.
   */
  private loadPrivateKey(): void {
    if (!this.config.privateKey) {
      this.privateKeyObject = null;
      return;
    }

    try {
      // Handle escaped newlines from single-line .env values.
      const cleanedKey = this.config.privateKey.replace(/\\n/g, "\n").trim();

      this.privateKeyObject = crypto.createPrivateKey({
        key: cleanedKey,
        format: "pem",
      });
    } catch (error) {
      console.error("❌ Error loading WAF Agent private key:", error);
      console.error(
        "   Please check that WAF_AGENT_PRIVATE_KEY in .env contains a valid PEM private key."
      );
      this.privateKeyObject = null;
    }
  }

  /**
   * Report the credential posture once at startup so misconfiguration is
   * obvious in the logs rather than at the first failed toggle.
   */
  private logConfiguration(): void {
    const { endpoint } = this.config;
    const missing = this.missingCredentials();

    if (!this.credentialsRequired) {
      console.log(
        `🔓 WAF Agent at ${endpoint.url} is local (${endpoint.reason}). ` +
          "Signing key and auth token are optional."
      );

      const provided = [
        this.privateKeyObject ? "signing key" : null,
        this.config.authToken ? "auth token" : null,
      ].filter(Boolean);

      if (provided.length > 0) {
        console.log(
          `   ${provided.join(" and ")} configured — requests will still be authenticated.`
        );
      }
      return;
    }

    if (missing.length > 0) {
      console.warn(
        `⚠️  WAF Agent at ${endpoint.url} is remote (${endpoint.reason}) but ` +
          `${missing.join(" and ")} missing. WAF agent calls will fail until configured.`
      );
      return;
    }

    console.log(
      `🔒 WAF Agent at ${endpoint.url} is remote (${endpoint.reason}). ` +
        "Requests are signed and authenticated."
    );

    if (endpoint.protocol === "http:") {
      console.warn(
        "⚠️  WAF_AGENT_URL uses plain http:// over a public network — the auth " +
          "token is sent in cleartext. Use https:// or a private tunnel."
      );
    }
  }

  /** Names of the credentials that are required here but not configured. */
  private missingCredentials(): string[] {
    if (!this.credentialsRequired) return [];

    const missing: string[] = [];
    if (!this.privateKeyObject) missing.push("WAF_AGENT_PRIVATE_KEY");
    if (!this.config.authToken) missing.push("WAF_AGENT_AUTH_TOKEN");
    return missing;
  }

  /**
   * Block the call when a remote agent is configured without credentials.
   * Local agents always pass.
   */
  private assertCredentialsConfigured(): void {
    const missing = this.missingCredentials();
    if (missing.length === 0) return;

    throw new Error(
      `WAF agent at ${this.config.endpoint.url} is remote (${this.config.endpoint.reason}), ` +
        `so ${missing.join(" and ")} must be set in .env. ` +
        "Credentials are only optional when the agent runs on localhost or a private network address."
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
   *
   * Wraps transport failures with the target URL, because a bare
   * "fetch failed" from undici gives no hint about which host was unreachable.
   */
  private async agentFetch<T>(
    path: string,
    init: { method: string; body?: string; includeJson: boolean }
  ): Promise<T> {
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
        `Could not reach WAF agent at ${target}: ${detail}. ` +
          "Check that the agent is running and that WAF_AGENT_URL is correct."
      );
    }

    if (!response.ok) {
      const errorBody = await response.text().catch(() => "");
      const hint =
        response.status === 401 || response.status === 403
          ? " (the agent rejected the credentials — check WAF_AGENT_AUTH_TOKEN and that the agent holds the matching public key)"
          : "";
      throw new Error(
        `WAF Agent returned ${response.status}: ${errorBody || response.statusText}${hint}`
      );
    }

    return (await response.json()) as T;
  }

  /**
   * Generate an RSA signature for the data.
   * Matches test_toggle.sh exactly: SHA256 with PSS padding and a maximum
   * salt length (Python's padding.PSS.MAX_LENGTH).
   *
   * Returns null when no key is configured, which only reaches this point for
   * a trusted local agent — assertCredentialsConfigured() rejects the remote
   * case before we get here.
   */
  private signData(data: string): string | null {
    if (!this.privateKeyObject) return null;

    try {
      const sign = crypto.createSign("sha256");
      sign.update(data, "utf-8");
      sign.end();

      const signature = sign.sign({
        key: this.privateKeyObject,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
      });

      return signature.toString("base64");
    } catch (error) {
      throw new Error(
        `Failed to sign data for WAF agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Toggle WAF status for a domain via the agent.
   */
  async toggleWAF(domain: string, enabled: boolean): Promise<ToggleWAFResponse> {
    this.assertCredentialsConfigured();

    // Data to sign: "domain|enabled" with a lowercase boolean string.
    const enabledStr = enabled ? "true" : "false";
    const signature = this.signData(`${domain}|${enabledStr}`);

    const requestBody: ToggleWAFRequest = { domain, enabled };
    if (signature) requestBody.signature = signature;

    const result = await this.agentFetch<ToggleWAFResponse>("/waf/toggle", {
      method: "POST",
      body: JSON.stringify(requestBody),
      includeJson: true,
    });

    if (result.status !== "OK") {
      throw new Error(
        `WAF Agent returned non-OK status: ${result.message || "Unknown error"}`
      );
    }

    return result;
  }

  /**
   * Check if the agent is reachable.
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

  /**
   * Ban or unban an IP address for the given domains.
   */
  async banIP(
    ip: string,
    domains: string[],
    action: "ban" | "unban"
  ): Promise<{ ok: boolean; results: Array<{ domain: string; changed: boolean; message: string }> }> {
    this.assertCredentialsConfigured();

    return this.agentFetch<{
      ok: boolean;
      results: Array<{ domain: string; changed: boolean; message: string }>;
    }>("/ban", {
      method: "POST",
      body: JSON.stringify({ ip, domains, action }),
      includeJson: true,
    });
  }

  /**
   * Get IP ban status from the agent.
   */
  async getIPBanStatus(): Promise<{
    domains: Array<{ domain: string; blocked_ips: string[]; blocked_count: number }>;
    total_blocked_ips: number;
  }> {
    this.assertCredentialsConfigured();

    return this.agentFetch<{
      domains: Array<{ domain: string; blocked_ips: string[]; blocked_count: number }>;
      total_blocked_ips: number;
    }>("/status", { method: "GET", includeJson: false });
  }

  /**
   * Configuration snapshot for diagnostics. Reports whether credentials are
   * present, never what they are.
   */
  getStatusInfo(): WAFAgentStatusInfo {
    const missing = this.missingCredentials();
    const { endpoint } = this.config;

    return {
      url: endpoint.url,
      hostname: endpoint.hostname,
      isLocal: endpoint.isLocal,
      reason: endpoint.reason,
      credentialsRequired: this.credentialsRequired,
      hasPrivateKey: this.privateKeyObject !== null,
      hasAuthToken: this.config.authToken.length > 0,
      ready: missing.length === 0,
      missing,
    };
  }
}

// Export singleton instance. The constructor is designed not to throw, but the
// guard keeps a startup failure from taking the whole server down.
let wafAgentService: WAFAgentService;
try {
  wafAgentService = new WAFAgentService();
} catch (error) {
  console.error("❌ Failed to initialize WAF Agent Service:", error);
  console.error("   Server will continue but WAF agent calls will fail.");
  wafAgentService = new WAFAgentService();
}

export { wafAgentService, WAFAgentService };
