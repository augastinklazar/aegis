# Aegis 🛡️

**Autonomous Agent Zero-Trust Gateway & Transactional Sandbox**

[![Go Report Card](https://goreportcard.com/badge/github.com/augastinklazar/aegis)](https://goreportcard.com/report/github.com/augastinklazar/aegis)
[![CI](https://github.com/augastinklazar/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/augastinklazar/aegis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Traditional OAuth 2.0/2.1 scopes (like `stripe.write` or `gmail.modify`) were built for deterministic apps, not probabilistic LLM agents. An agent given `stripe.write` to refund \$10 can hallucinate, get prompt-injected, and drain \$50,000.

**Aegis** sits between your AI agents (Claude Code, LangGraph, CrewAI, AutoGen, custom MCP clients) and upstream APIs. It provides credentialless phantom token injection, semantic CEL policy gating, in-flight human-in-the-loop (HITL) freezing, and a tamper-evident Merkle audit trail.

---

## Architecture

```
 AI Agent / MCP Client (Claude, LangGraph, CrewAI)
        │
        │ Uses Ephemeral Phantom Token (`ag_tok_...`)
        ▼
┌──────────────────────────────────────────────────────────────┐
│                    AEGIS AUTH GATEWAY                        │
│                                                              │
│ 1. Identity & Token Broker (RFC 8693 & draft-rosenberg-aauth)│
│    • On-Behalf-Of exchange with `sub` + `act` claims         │
│    • Ephemeral TTL & atomic call-quota tracker               │
│                                                              │
│ 2. Deterministic Transactional Sandbox (CEL Policy Engine)   │
│    • Semantic payload rules: request.body.amount <= 2500     │
│    • AST SQL & Bash firewall (blocks DROP, rm -rf, curl)     │
│    • Stateful cumulative budgets in SQLite WAL               │
│                                                              │
│ 3. Async HITL Escalation Engine                              │
│    • Channel parking freezes in-flight HTTP or MCP tool call │
│    • Free dispatchers: Telegram, Discord, Slack, WebPush     │
│    • Cryptographic Passkey (WebAuthn TouchID/FaceID) sign-off│
│                                                              │
│ 4. Vault & Egress Injector + Merkle Audit Logger             │
│    • Decrypts real upstream secret (AES-256-GCM)             │
│    • Strips phantom token, injects real key over the wire    │
│    • Appends SHA-256 hash-chained proof to immutable ledger  │
└──────────────────────────────┬───────────────────────────────┘
                               │ Real Upstream Token Injected
                               ▼
            External APIs (Stripe, GitHub, Postgres, AWS)
```

---

## 5 Foundational Standards

1. **OAuth 2.0 Token Exchange (RFC 8693) & OBO (`act` claims)**: Upstream APIs and audit logs know which human authorized the task and which specific agent instance executed it (`act.sub = "agent_id"`, `act.task_id = "tx_99"`).
2. **AAuth (draft-rosenberg-oauth-aauth)**: Asynchronous authorization with natural language `reason` parameters and HTTP 202 polling handles.
3. **Rich Authorization Requests (RAR - RFC 9396)**: Replaces flat string scopes with mathematical JSON attenuations (`{"max_amount_cents": 2000, "currency": "USD", "max_calls": 1}`).
4. **Credentialless Secret Injection (Phantom Tokens)**: Agents never see real upstream keys. They hold short-lived tokens (`ag_tok_...`). Aegis decrypts and swaps the real credential at egress.
5. **Dual-Transport Interception**: Intercepts both REST/HTTP APIs and Model Context Protocol (MCP) JSON-RPC 2.0 stdio & SSE tools.

---

## 30-Second Quickstart

### 1. Initialize local vault & keys
```bash
aegis init
```

### 2. Store your real upstream API key
```bash
aegis vault set stripe_prod sk_test_your_actual_stripe_key_here
```

### 3. Start the gateway daemon
```bash
aegis serve --port 8080
```
Open **`http://localhost:8080`** for the real-time dashboard, visual policy simulator, and Passkey approval UI.

### 4. Issue a task-scoped phantom token
```bash
aegis token issue --agent refund-bot --service stripe_prod --max-calls 5
```
Output:
```
✓ Task-Scoped Phantom Token Issued:
  Token:     ag_tok_18e32b570aa87e320281257e8f2a6a99ac15cd17c71d8551
  Service:   stripe_prod
  Agent:     refund-bot
  ExpiresIn: 600s
  Max Calls: 5
```

### 5. Call API through Aegis
```bash
curl -X POST http://localhost:8080/proxy/stripe_prod/v1/refunds \
  -H "Authorization: Bearer ag_tok_18e32b570aa87e320281257e8f2a6a99ac15cd17c71d8551" \
  -H "Content-Type: application/json" \
  -H "X-Aegis-Reason: Refunding customer for accidental double payment" \
  -d '{"amount": 1500, "currency": "usd"}'
```
- Small refunds ($\le \$25$) execute instantly.
- Medium refunds ($\$25 - \$500$) trigger human escalation: Aegis freezes the HTTP connection in-flight, alerts your Telegram/Discord, and waits for your Passkey sign-off.
- Catastrophic refunds ($> \$500$) are deterministically blocked with zero network egress.

---

## Wrapping MCP Servers

Wrap any existing Model Context Protocol (MCP) server over stdio with full policy enforcement:

```bash
aegis wrap-mcp --agent sql-analyst -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb
```
Aegis inspects incoming `tools/call` JSON-RPC payloads before they reach the database:
- Safe `SELECT` queries pass through.
- Unbounded `DELETE` or `DROP TABLE` queries are rejected deterministically before execution.

---

## Declarative YAML Policy Example

```yaml
version: "1.0"
agent_id: "finance-bot"
upstream_service: "stripe_prod"
rules:
  # Allow micro-refunds automatically
  - name: "allow_micro_refunds"
    match: "request.method == 'POST' && request.path == '/v1/refunds'"
    allow_if: "int(request.body.amount) <= 2500"

  # Escalate medium refunds to human approver via Telegram
  - name: "escalate_medium_refunds"
    match: "request.method == 'POST' && request.path == '/v1/refunds'"
    escalate_if: "int(request.body.amount) > 2500 && int(request.body.amount) <= 50000"
    approvers: ["telegram:finance_leads", "webpush:owner"]
    timeout_seconds: 300

  # Hard deny catastrophic spend
  - name: "block_catastrophic_refunds"
    match: "request.method == 'POST' && request.path == '/v1/refunds'"
    deny_if: "int(request.body.amount) > 50000"
```

10 pre-configured policies are included out of the box in `policies/presets/`:
- `stripe-safe.yaml`
- `github-no-force-push.yaml`
- `postgres-readonly.yaml`
- `gmail-draft-only.yaml`
- `aws-guard.yaml`
- `slack-announce.yaml`
- `bash-safe.yaml`
- `filesystem-sandbox.yaml`
- `database-crud-budget.yaml`
- `browser-exec.yaml`

---

## Tamper-Evident Merkle Audit Trail

Every tool call and human approval signature is appended to a cryptographic SHA-256 hash-chained ledger in SQLite:

$$\text{record\_hash}_n = \text{SHA256}(\text{seq}_n \parallel \text{record\_hash}_{n-1} \parallel \text{timestamp} \parallel \text{agent\_id} \parallel \text{payload\_hash} \parallel \text{decision} \parallel \text{signature})$$

Verify ledger integrity with one command:
```bash
aegis verify
```
```
✓ Cryptographic Audit Trail Verified (SOC-2/HIPAA Grade)
  Total Blocks: 42
  Tip Hash:     3a9f0e8d...4f2b
```

---

## SDKs

### Python (`aegis-agent-sdk`)
```python
from aegis_agent_sdk import AegisClient

client = AegisClient("http://localhost:8080")
client.exchange_token(actor_token="bot", subject_token="admin", audience="stripe_prod")

resp = client.request("POST", "stripe_prod", "/v1/refunds", json={"amount": 2000})
```

### TypeScript / Vercel AI SDK (`@aegis-auth/sdk`)
```typescript
import { AegisClient } from "@aegis-auth/sdk";

const aegis = new AegisClient({ baseUrl: "http://localhost:8080" });
await aegis.exchangeToken({
  actorToken: "bot",
  subjectToken: "admin",
  audience: "stripe_prod"
});

const secureFetch = aegis.createFetch("stripe_prod");
await secureFetch("/v1/refunds", { method: "POST", body: JSON.stringify({ amount: 2000 }) });
```

---

## Production Deployment

### Docker
```bash
docker run -d -p 8080:8080 \
  -v aegis-data:/etc/aegis/data \
  -e AEGIS_VAULT_KEY="your-32-byte-master-key-hex" \
  ghcr.io/augastinklazar/aegis:latest
```

---

## License

MIT © Aegis Contributors
