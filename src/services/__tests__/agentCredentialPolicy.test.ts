import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { resolveAgentEndpoint } from "../../utils/agentEndpoint";
import { WAFAgentService } from "../wafAgent";

interface CapturedRequest {
  authorization: string | null;
  body: Record<string, unknown>;
}

/**
 * Stand up a throwaway agent on loopback that records what it receives and
 * always answers OK. Returns the port plus the captured requests.
 */
async function withStubAgent(
  run: (port: number, captured: CapturedRequest[]) => Promise<void>
): Promise<void> {
  const captured: CapturedRequest[] = [];

  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : {};
      captured.push({
        authorization: req.headers.authorization ?? null,
        body,
      });
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          status: "OK",
          message: "ok",
          domain: body.domain,
          modsecurity_status: "on",
        })
      );
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    await run((server.address() as AddressInfo).port, captured);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function isLocal(url: string): boolean {
  return resolveAgentEndpoint(url, url).isLocal;
}

/**
 * Build a service with a specific environment, silencing the constructor's
 * startup banner so test output stays readable.
 */
function serviceWith(overrides: Record<string, string | undefined>) {
  const original = new Map<string, string | undefined>();
  const names = new Set([
    "WAF_AGENT_URL",
    "WAF_AGENT_PRIVATE_KEY",
    "WAF_AGENT_AUTH_TOKEN",
    ...Object.keys(overrides),
  ]);

  for (const name of names) {
    original.set(name, process.env[name]);
    const value = overrides[name];
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }

  const { log, warn, error } = console;
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};

  try {
    return new WAFAgentService();
  } finally {
    console.log = log;
    console.warn = warn;
    console.error = error;
    for (const [name, value] of original) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}

test("only loopback addresses are classified as local", () => {
  const localUrls = [
    "http://localhost:8080",
    "https://LOCALHOST:8080",
    "http://127.0.0.1:8080",
    "http://127.1.2.3:8080",
    "http://[::1]:8080",
    "http://[::ffff:127.0.0.1]:8080",
    "http://agent.localhost:8080",
  ];

  for (const url of localUrls) {
    assert.equal(isLocal(url), true, `${url} should be local`);
  }
});

/**
 * The agent trusts only loopback callers (waf-agent src/security.py
 * is_trusted_local_request). These two lists must stay in lockstep with that
 * rule: anything this side called "local" that the agent would not is a 403
 * waiting to happen.
 */
test("private network addresses require credentials, matching the agent", () => {
  const remoteUrls = [
    "http://10.0.5.20:8080",
    "http://172.16.0.1:8080",
    "http://192.168.1.50:8080",
    "http://169.254.10.10:8080",
    "http://100.64.0.1:8080", // Tailscale / CGNAT
    "http://[fd00::1]:8080", // IPv6 unique local
    "http://[fe80::1]:8080", // IPv6 link-local
    "http://waf-agent:8080", // Docker Compose service name
    "http://agent.local:8080",
    "http://agent.internal:8080",
    "http://0.0.0.0:8080", // unspecified, not loopback
  ];

  for (const url of remoteUrls) {
    assert.equal(isLocal(url), false, `${url} should require credentials`);
  }
});

test("public addresses and domains are classified as remote", () => {
  const remoteUrls = [
    "http://196.188.250.141:8080", // the deployed agent
    "http://8.8.8.8:8080",
    "https://waf.example.com",
    "https://example.com:8080",
    "http://11.0.0.1:8080",
    "http://[2001:4860:4860::8888]:8080",
  ];

  for (const url of remoteUrls) {
    assert.equal(isLocal(url), false, `${url} should be remote`);
  }
});

test("an unparseable url fails closed as remote", () => {
  const endpoint = resolveAgentEndpoint("not a url", "http://localhost:8080");
  assert.equal(endpoint.isLocal, false);
  assert.match(endpoint.reason, /not a valid URL/);
});

test("a blank url falls back to the default", () => {
  assert.equal(resolveAgentEndpoint("", "http://localhost:8080").isLocal, true);
  assert.equal(
    resolveAgentEndpoint(undefined, "http://localhost:8080").isLocal,
    true
  );
});

test("quotes and trailing slashes are stripped from the url", () => {
  const endpoint = resolveAgentEndpoint(
    '"http://localhost:8080/"',
    "http://localhost:9999"
  );
  assert.equal(endpoint.url, "http://localhost:8080");
  assert.equal(endpoint.isLocal, true);
});

test("a local agent needs no key or token", () => {
  const service = serviceWith({ WAF_AGENT_URL: "http://localhost:8080" });
  const status = service.getStatusInfo();

  assert.equal(status.isLocal, true);
  assert.equal(status.credentialsRequired, false);
  assert.equal(status.ready, true);
  assert.deepEqual(status.missing, []);
});

test("a remote agent without credentials is not ready and names what is missing", () => {
  const service = serviceWith({ WAF_AGENT_URL: "http://196.188.250.141:8080" });
  const status = service.getStatusInfo();

  assert.equal(status.isLocal, false);
  assert.equal(status.credentialsRequired, true);
  assert.equal(status.ready, false);
  assert.deepEqual(status.missing, [
    "WAF_AGENT_PRIVATE_KEY",
    "WAF_AGENT_AUTH_TOKEN",
  ]);
});

test("a remote agent call throws before any network request is attempted", async () => {
  const service = serviceWith({ WAF_AGENT_URL: "http://196.188.250.141:8080" });

  await assert.rejects(
    () => service.toggleWAF("example.com", true),
    /WAF_AGENT_PRIVATE_KEY and WAF_AGENT_AUTH_TOKEN must be set/
  );
  await assert.rejects(
    () => service.banIP("1.2.3.4", ["example.com"], "ban"),
    /must be set/
  );
  await assert.rejects(() => service.getIPBanStatus(), /must be set/);
});

test("no environment flag can bypass enforcement for a remote agent", () => {
  // A tunnelled agent is always addressed by its private endpoint, so it
  // already classifies as local. Any bypass here could only ever enable an
  // unauthenticated public agent, which is the case this policy exists to stop.
  const bypassAttempts = [
    "WAF_AGENT_ALLOW_INSECURE",
    "GEO_AGENT_ALLOW_INSECURE",
    "WAF_AGENT_SKIP_AUTH",
    "NODE_ENV",
  ];

  for (const name of bypassAttempts) {
    const service = serviceWith({
      WAF_AGENT_URL: "http://196.188.250.141:8080",
      [name]: "true",
    });
    const status = service.getStatusInfo();

    assert.equal(
      status.credentialsRequired,
      true,
      `${name} must not relax enforcement`
    );
    assert.equal(status.ready, false, `${name} must not mark the agent ready`);
  }
});

test("a token on a local agent is still reported as configured", () => {
  const service = serviceWith({
    WAF_AGENT_URL: "http://localhost:8080",
    WAF_AGENT_AUTH_TOKEN: "local-token",
  });
  const status = service.getStatusInfo();

  assert.equal(status.hasAuthToken, true);
  assert.equal(status.credentialsRequired, false);
  assert.equal(status.ready, true);
});

test("an invalid private key does not crash construction", () => {
  const service = serviceWith({
    WAF_AGENT_URL: "http://localhost:8080",
    WAF_AGENT_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----",
  });

  assert.equal(service.getStatusInfo().hasPrivateKey, false);
});

test("a valid private key is loaded and reported", () => {
  const { privateKey } = require("node:crypto").generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  const service = serviceWith({
    WAF_AGENT_URL: "http://196.188.250.141:8080",
    WAF_AGENT_PRIVATE_KEY: privateKey,
    WAF_AGENT_AUTH_TOKEN: "remote-token",
  });
  const status = service.getStatusInfo();

  assert.equal(status.hasPrivateKey, true);
  assert.equal(status.credentialsRequired, true);
  assert.equal(status.ready, true);
  assert.deepEqual(status.missing, []);
});

test("a local agent receives an unsigned, unauthenticated request", async () => {
  await withStubAgent(async (port, captured) => {
    const service = serviceWith({ WAF_AGENT_URL: `http://127.0.0.1:${port}` });

    const result = await service.toggleWAF("example.com", true);
    assert.equal(result.status, "OK");

    assert.equal(captured.length, 1);
    assert.equal(captured[0].authorization, null, "no Authorization header");
    assert.equal("signature" in captured[0].body, false, "no signature field");
    assert.deepEqual(captured[0].body, { domain: "example.com", enabled: true });
  });
});

test("configured credentials are used even against a local agent, and the signature verifies", async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  await withStubAgent(async (port, captured) => {
    const service = serviceWith({
      WAF_AGENT_URL: `http://127.0.0.1:${port}`,
      WAF_AGENT_PRIVATE_KEY: privateKey,
      WAF_AGENT_AUTH_TOKEN: "secret-token",
    });

    await service.toggleWAF("example.com", false);

    assert.equal(captured[0].authorization, "Bearer secret-token");

    // Verify exactly the way the agent does: SHA256 + PSS over "domain|enabled".
    const verifier = crypto.createVerify("sha256");
    verifier.update("example.com|false", "utf-8");
    verifier.end();

    const valid = verifier.verify(
      {
        key: crypto.createPublicKey(publicKey),
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
      },
      Buffer.from(String(captured[0].body.signature), "base64")
    );

    assert.equal(valid, true, "signature must verify against the public key");
  });
});
