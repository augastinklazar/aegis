/**
 * @aegis-auth/sdk
 * Zero-trust credential injection & MCP security middleware for AI agents.
 */

export interface AegisConfig {
  baseUrl?: string;
  token?: string;
  agentId?: string;
  taskId?: string;
}

export interface TokenExchangeOptions {
  actorToken: string;
  subjectToken: string;
  audience: string;
  scope?: string;
  taskId?: string;
  reason?: string;
  ttlSeconds?: number;
  maxCalls?: number;
  authorizationDetails?: any;
}

export class AegisClient {
  private baseUrl: string;
  private token?: string;
  private agentId?: string;
  private taskId?: string;

  constructor(config: AegisConfig = {}) {
    this.baseUrl = (config.baseUrl || "http://localhost:8080").replace(/\/$/, "");
    this.token = config.token;
    this.agentId = config.agentId;
    this.taskId = config.taskId;
  }

  async exchangeToken(options: TokenExchangeOptions): Promise<{ accessToken: string; jwt?: string; expiresIn: number }> {
    const res = await fetch(`${this.baseUrl}/v1/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        actor_token: options.actorToken,
        subject_token: options.subjectToken,
        audience: options.audience,
        scope: options.scope || "",
        task_id: options.taskId || this.taskId || "",
        reason: options.reason || "",
        ttl_seconds: options.ttlSeconds || 600,
        max_calls: options.maxCalls || 0,
        authorization_details: options.authorizationDetails ? JSON.stringify(options.authorizationDetails) : undefined,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Aegis token exchange failed (${res.status}): ${errText}`);
    }

    const data = await res.json();
    this.token = data.access_token;
    return {
      accessToken: data.access_token,
      jwt: data.jwt,
      expiresIn: data.expires_in,
    };
  }

  /**
   * Returns a custom fetch instance that automatically routes requests
   * through the Aegis gateway with phantom token authentication and PII filtering.
   */
  createFetch(service: string) {
    return async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
      let targetPath = typeof input === "string" ? input : input.toString();
      try {
        const u = new URL(targetPath);
        targetPath = u.pathname + u.search;
      } catch (e) {
        // relative path
      }
      targetPath = targetPath.replace(/^\//, "");

      const proxyUrl = `${this.baseUrl}/proxy/${service}/${targetPath}`;
      const headers = new Headers(init.headers || {});

      if (this.token) {
        headers.set("Authorization", `Bearer ${this.token}`);
      }
      if (this.agentId) {
        headers.set("X-Aegis-Agent", this.agentId);
      }

      return fetch(proxyUrl, {
        ...init,
        headers,
      });
    };
  }

  /**
   * Vercel AI SDK middleware hook.
   * Intercepts tool calls and evaluates against Aegis policies.
   */
  wrapTool(toolName: string, executeFn: (args: any) => Promise<any>) {
    return async (args: any, context?: any) => {
      const evalRes = await fetch(`${this.baseUrl}/v1/sandbox/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tool: toolName,
          args: args,
          agent_id: this.agentId || "typescript-agent",
          task_id: this.taskId || "session",
          service: `mcp:${toolName}`,
        }),
      });

      if (evalRes.ok) {
        const decision = await evalRes.json();
        if (decision.decision === "DENY") {
          throw new Error(`Tool execution blocked by Aegis Policy: ${decision.reason}`);
        }
      }

      return executeFn(args);
    };
  }
}
