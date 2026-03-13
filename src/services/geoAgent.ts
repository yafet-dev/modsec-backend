/**
 * Geo Agent Service
 * Handles communication with the Geo Agent to manage geo access control
 */

interface GeoAgentConfig {
  url: string;
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
    // Strip quotes from environment variables (common issue with .env files)
    // Default to WAF_AGENT_URL (port 8080) since geo endpoints are now in the same service
    const agentUrl = (process.env.GEO_AGENT_URL || process.env.WAF_AGENT_URL || "http://localhost:8080")
      .replace(/^["']|["']$/g, "") // Remove surrounding quotes
      .trim();
    const authToken = (process.env.GEO_AGENT_AUTH_TOKEN || process.env.WAF_AGENT_AUTH_TOKEN || "test-token")
      .replace(/^["']|["']$/g, "") // Remove surrounding quotes
      .trim();

    this.config = {
      url: agentUrl,
      authToken,
    };
  }

  /**
   * Set the geo access mode (allow_only or deny_only)
   */
  async setMode(mode: "allow_only" | "deny_only", force: boolean = false): Promise<GeoAgentModeResponse> {
    try {
      const response = await fetch(`${this.config.url}/v1/geo/mode`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.config.authToken}`,
        },
        body: JSON.stringify({
          mode,
          force,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Geo Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as GeoAgentModeResponse;
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with Geo agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Add a country to the allow list
   */
  async addAllowCountry(country: string): Promise<GeoAgentCountryResponse> {
    try {
      const response = await fetch(`${this.config.url}/v1/geo/allow`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.config.authToken}`,
        },
        body: JSON.stringify({
          country,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Geo Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as GeoAgentCountryResponse;
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with Geo agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Remove a country from the allow list
   */
  async removeAllowCountry(country: string, force: boolean = false): Promise<GeoAgentCountryResponse> {
    try {
      const response = await fetch(`${this.config.url}/v1/geo/allow/${country}?force=${force}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${this.config.authToken}`,
        },
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Geo Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as GeoAgentCountryResponse;
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with Geo agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Add a country to the deny list
   */
  async addDenyCountry(country: string): Promise<GeoAgentCountryResponse> {
    try {
      const response = await fetch(`${this.config.url}/v1/geo/deny`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.config.authToken}`,
        },
        body: JSON.stringify({
          country,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Geo Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as GeoAgentCountryResponse;
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with Geo agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Remove a country from the deny list
   */
  async removeDenyCountry(country: string): Promise<GeoAgentCountryResponse> {
    try {
      const response = await fetch(`${this.config.url}/v1/geo/deny/${country}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${this.config.authToken}`,
        },
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Geo Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as GeoAgentCountryResponse;
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with Geo agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Get current geo access status from agent
   */
  async getStatus(): Promise<GeoAgentStatusResponse> {
    try {
      const response = await fetch(`${this.config.url}/v1/geo/status`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${this.config.authToken}`,
        },
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(
          `Geo Agent returned ${response.status}: ${errorBody || response.statusText}`
        );
      }

      const result = await response.json() as GeoAgentStatusResponse;
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(
        `Failed to communicate with Geo agent: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
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
      const response = await fetch(`${this.config.url}/health`, {
        method: "GET",
        timeout: 5000,
      } as any);

      return response.ok;
    } catch (error) {
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
