import crypto from "crypto";

/**
 * WAF Agent Service
 * Handles communication with the WAF agent to toggle ModSecurity on/off
 * 
 * Communication flow (matches test_toggle.sh):
 * 1. Backend has PRIVATE key (to sign requests)
 * 2. Agent has PUBLIC key (to verify signatures)
 * 3. Data format: "domain|enabled" where enabled is lowercase "true" or "false"
 * 4. Uses RSA PSS padding with SHA256
 */

interface WAFAgentConfig {
  url: string;
  privateKey: string;
  authToken: string;
}

interface ToggleWAFRequest {
  domain: string;
  enabled: boolean;
  signature: string;
}

interface ToggleWAFResponse {
  status: string;
  message: string;
  domain: string;
  modsecurity_status: string;
}

class WAFAgentService {
  private config: WAFAgentConfig;
  private privateKeyObject: crypto.KeyObject | null = null;

  constructor() {
    // Strip quotes from environment variables (common issue with .env files)
    const agentUrl = (process.env.WAF_AGENT_URL || "http://localhost:8080")
      .replace(/^["']|["']$/g, "") // Remove surrounding quotes
      .trim();
    const privateKeyContent = (process.env.WAF_AGENT_PRIVATE_KEY || "")
      .replace(/^["']|["']$/g, "") // Remove surrounding quotes
      .trim();
    const authToken = (process.env.WAF_AGENT_AUTH_TOKEN || "test-token")
      .replace(/^["']|["']$/g, "") // Remove surrounding quotes
      .trim();

    this.config = {
      url: agentUrl,
      privateKey: privateKeyContent,
      authToken,
    };

    // Load private key on initialization
    this.loadPrivateKey();
  }

  /**
   * Load the private key from environment variable
   * The key should be in PEM format (can include newlines, headers, etc.)
   * This method is safe and won't crash the server if the key is missing or invalid
   */
  private loadPrivateKey(): void {
    try {
      if (!this.config.privateKey || this.config.privateKey.trim() === "") {
        console.warn(
          "⚠️  WAF_AGENT_PRIVATE_KEY not set in environment. WAF agent calls will fail until configured."
        );
        return;
      }

      // Clean up the key string (remove extra whitespace, handle newlines)
      const cleanedKey = this.config.privateKey
        .replace(/\\n/g, "\n") // Handle escaped newlines
        .trim();

      // Create private key object from PEM string
      // Handles both single-line and multi-line PEM formats
      this.privateKeyObject = crypto.createPrivateKey({
        key: cleanedKey,
        format: "pem",
      });
      console.log("✅ WAF Agent private key loaded successfully from environment variable");
    } catch (error) {
      console.error("❌ Error loading WAF Agent private key:", error);
      console.error(
        "   Please check that WAF_AGENT_PRIVATE_KEY in .env contains a valid PEM private key."
      );
      this.privateKeyObject = null;
      // Don't throw - allow server to start even if key is invalid
    }
  }

  /**
   * Generate RSA signature for the data
   * Matches test_toggle.sh implementation exactly:
   * - Data format: "domain|enabled" where enabled is lowercase "true" or "false"
   * - Uses RSA PSS padding with SHA256
   * - Salt length: MAX_LENGTH (matches Python's padding.PSS.MAX_LENGTH)
   */
  private signData(data: string): string {
    if (!this.privateKeyObject) {
      throw new Error(
        "Private key not loaded. Cannot sign request to WAF agent. Please set WAF_AGENT_PRIVATE_KEY in .env"
      );
    }

    try {
      // Create sign object with SHA256 (matches Python's hashes.SHA256())
      const sign = crypto.createSign("sha256");
      sign.update(data, "utf-8");
      sign.end();

      // Sign with PSS padding (matches Python's padding.PSS with MAX_LENGTH salt)
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
   * Toggle WAF status for a domain via the agent
   * Matches test_toggle.sh communication pattern exactly
   */
  async toggleWAF(domain: string, enabled: boolean): Promise<ToggleWAFResponse> {
    if (!this.privateKeyObject) {
      throw new Error(
        "WAF Agent private key not available. Please set WAF_AGENT_PRIVATE_KEY in .env file."
      );
    }

    // Prepare data for signing: domain|enabled (lowercase boolean string)
    // This matches test_toggle.sh: enabled_str is lowercase "true" or "false"
    const enabledStr = enabled ? "true" : "false";
    const dataToSign = `${domain}|${enabledStr}`;

    // Generate signature (matches test_toggle.sh Python implementation)
    const signature = this.signData(dataToSign);

    // Prepare request
    const requestBody: ToggleWAFRequest = {
      domain,
      enabled,
      signature,
    };

    try {
      // Make request to agent
      const response = await fetch(`${this.config.url}/waf/toggle`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.config.authToken}`,
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `WAF Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as ToggleWAFResponse;

      if (result.status !== "OK") {
        throw new Error(
          `WAF Agent returned non-OK status: ${result.message || "Unknown error"}`
        );
      }

      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with WAF agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Check if agent is available
   */
  async checkHealth(): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.url}/health`, {
        method: "GET",
        timeout: 5000,
      } as any);

      return response.ok;
    } catch (error) {
      return false;
    }
  }

  /**
   * Ban or unban an IP address for domains
   */
  async banIP(
    ip: string,
    domains: string[],
    action: "ban" | "unban"
  ): Promise<{ ok: boolean; results: Array<{ domain: string; changed: boolean; message: string }> }> {
    try {
      const response = await fetch(`${this.config.url}/ban`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.config.authToken}`,
        },
        body: JSON.stringify({
          ip,
          domains,
          action,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `WAF Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as { ok: boolean; results: Array<{ domain: string; changed: boolean; message: string }> };
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with WAF agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Get IP ban status from agent
   */
  async getIPBanStatus(): Promise<{
    domains: Array<{ domain: string; blocked_ips: string[]; blocked_count: number }>;
    total_blocked_ips: number;
  }> {
    try {
      const response = await fetch(`${this.config.url}/status`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${this.config.authToken}`,
        },
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `WAF Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as { domains: Array<{ domain: string; blocked_ips: string[]; blocked_count: number }>; total_blocked_ips: number };
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with WAF agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }
}

// Export singleton instance
// Wrap in try-catch to prevent server crash if initialization fails
let wafAgentService: WAFAgentService;
try {
  wafAgentService = new WAFAgentService();
} catch (error) {
  console.error("❌ Failed to initialize WAF Agent Service:", error);
  console.error("   Server will continue but WAF agent calls will fail.");
  // Create a dummy service that will throw errors when used
  wafAgentService = new WAFAgentService();
}

export { wafAgentService };

