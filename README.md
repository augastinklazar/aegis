# Aegis 🛡️

**Zero-Trust Agentic Security Gateway & Transactional Sandbox**

[![Go Report Card](https://goreportcard.com/badge/github.com/augastinklazar/aegis)](https://goreportcard.com/report/github.com/augastinklazar/aegis)
[![CI](https://github.com/augastinklazar/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/augastinklazar/aegis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Aegis sits between AI agents (Claude Code, LangGraph, CrewAI, AutoGen, custom MCP tools) and real-world APIs or databases. It stops prompt injections, rogue tool calls, and credential leakage before they hit your infrastructure.

* **100% Free & Open-Source Locally:** No cloud required, no tracking, no subscription. Runs offline via SQLite.
* **Credentialless Secret Injection:** Agents only touch short-lived phantom tokens (`ag_tok_...`). Real API keys never leave the vault.
* **Semantic Policy Sandbox:** Microsecond Google CEL rules + AST firewalls for SQL and Bash.
* **In-Flight Human Approvals:** Freezes dangerous requests mid-stream for Telegram, Discord, Slack, or WebAuthn Passkey sign-off.
* **Tamper-Evident Ledger:** Cryptographic SHA-256 Merkle audit trail for SOC-2 and HIPAA compliance.

---

## ⚡ Beginner 3-Minute Quickstart (100% Free Local Setup)

No cloud account, no credit card, and no prior Go experience required.

### 1. Install or Build Aegis

**Option A: Using Go (1.22+)**
```bash
git clone https://github.com/augastinklazar/aegis.git
cd aegis
go build -o aegis cmd/aegis/main.go
```

**Option B: Using Docker**
```bash
docker run -d --name aegis -p 8080:8080 ghcr.io/augastinklazar/aegis:latest
```

---

### 2. Initialize Local Vault
Creates an encrypted SQLite database and prints your local master key:
```bash
./aegis init
```
*Tip: Save the printed `AEGIS_VAULT_KEY` to your environment or `.env` file.*

---

### 3. Store Upstream Secret in Vault
Store your real API key (e.g., Stripe, OpenAI, GitHub, or AWS). Your AI agent will never see this key:
```bash
./aegis vault set stripe_prod sk_test_your_real_stripe_key_here
```

---

### 4. Start Local Proxy Gateway
```bash
./aegis serve
```
Open **`http://localhost:8080`** in your browser to view the real-time visual dashboard, interactive policy simulator, and Passkey approval interface.

---

### 5. Issue a Task-Scoped Phantom Token
Generate a 10-minute, 5-call bounded token for your agent:
```bash
./aegis token issue --agent refund-bot --service stripe_prod --max-calls 5
```
Output:
```text
✓ Task-Scoped Phantom Token Issued:
  Token:     ag_tok_18e32b570aa87e320281257e8f2a6a99ac15cd17c71d8551
  Service:   stripe_prod
  Agent:     refund-bot
  ExpiresIn: 600s
  Max Calls: 5
```

---

### 6. Make a Safe Request
Point your agent or curl command to the local proxy:
```bash
curl -X POST http://localhost:8080/proxy/stripe_prod/v1/refunds \
  -H "Authorization: Bearer ag_tok_18e32b570aa87e320281257e8f2a6a99ac15cd17c71d8551" \
  -H "Content-Type: application/json" \
  -H "X-Aegis-Reason: Refunding customer for duplicate charge" \
  -d '{"amount": 1500, "currency": "usd"}'
```
* **$15 refund:** Within automatic limit. Aegis strips the phantom token, injects the real Stripe key, calls Stripe, and records the audit block.
* **$100 refund:** Exceeds limit. Aegis halts the request in-flight, sends an approval card to your phone/terminal, and resumes only after your sign-off.
* **$5,000 refund:** Violates hard policy. Aegis deterministically rejects the request without touching Stripe.

---

## 🤖 Master AI Agent Autonomous Setup Prompt

Copy and paste this prompt directly into any AI coding assistant (Claude Code, Cursor Agent, Devin, Aider, Copilot, Antigravity) to install, configure, and verify Aegis automatically:

```markdown
You are acting as an autonomous DevOps and Systems Engineer.
Your task is to clone, build, configure, test, and verify the Aegis Zero-Trust Agentic Gateway in this environment.

Follow these exact steps sequentially:

1. CLONE & BUILD:
   - Run: git clone https://github.com/augastinklazar/aegis.git
   - Change directory to aegis
   - Run: go test ./... to confirm all 18 unit and integration tests pass.
   - Run: go build -o aegis cmd/aegis/main.go
   - Run: go build -o aegis-cloud cmd/aegis-cloud/main.go

2. INITIALIZATION:
   - Run: ./aegis init
   - Capture the generated 64-character hex master key from the output and export it as AEGIS_VAULT_KEY.
   - Verify that ~/.aegis/vault.db was created with proper SQLite permissions.

3. VAULT ENCRYPTION TEST:
   - Store a test secret: ./aegis vault set test_service "sk_mock_secret_key_999"
   - Confirm storage: ./aegis vault list (ensure test_service is listed).

4. TOKEN BROKERAGE:
   - Issue a test phantom token:
     ./aegis token issue --agent autonomous-agent --service test_service --max-calls 3 --ttl 300
   - Extract the generated ag_tok_... token value from stdout.

5. VERIFY INTEGRITY:
   - Run: ./aegis verify
   - Ensure the cryptographic SHA-256 Merkle audit trail confirms 100% integrity.

6. REPORT READINESS:
   - Report binary status, vault status, test results, and provide the command to run the local gateway: ./aegis serve.
```

---

## 🏛️ Architecture

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

## 🛡️ 5 Core Security Capabilities

1. **RFC 8693 Token Exchange & On-Behalf-Of (`act` Claims):** Upstream services and logs know both the human user (`sub`) and the autonomous agent (`act.sub`).
2. **Asynchronous Authorization (AAuth):** Natural language `X-Aegis-Reason` tracking with HTTP 202 polling handles during long human approvals.
3. **Rich Authorization Requests (RAR - RFC 9396):** Replaces loose string scopes with strict payload bounds (`{"max_amount_cents": 2000, "currency": "USD"}`).
4. **Credentialless Secret Injection:** Agents never touch raw API keys; tokens expire automatically after TTL or maximum call counts.
5. **Dual REST & MCP Tool Interception:** Protects conventional HTTP webhooks and JSON-RPC Model Context Protocol (MCP) servers via stdio and SSE.

---

## 🧰 Wrapping MCP Tools

Protect any existing Model Context Protocol (MCP) server over standard input/output with zero code changes:

```bash
aegis wrap-mcp --agent sql-analyst -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb
```
Aegis inspects incoming `tools/call` JSON-RPC payloads before they touch your database:
* Safe `SELECT` queries pass through automatically.
* Unbounded `DELETE` or `DROP TABLE` queries are blocked deterministically.

---

## 📜 Declarative YAML Policy Example

```yaml
version: "1.0"
agent_id: "finance-bot"
upstream_service: "stripe_prod"
rules:
  # Micro-refunds execute automatically
  - name: "allow_micro_refunds"
    match: "request.method == 'POST' && request.path == '/v1/refunds'"
    allow_if: "int(request.body.amount) <= 2500"

  # Medium refunds freeze in-flight for mobile human sign-off
  - name: "escalate_medium_refunds"
    match: "request.method == 'POST' && request.path == '/v1/refunds'"
    escalate_if: "int(request.body.amount) > 2500 && int(request.body.amount) <= 50000"
    approvers: ["telegram:finance_leads", "webpush:owner"]
    timeout_seconds: 300

  # Catastrophic spend is hard-denied before egress
  - name: "block_catastrophic_refunds"
    match: "request.method == 'POST' && request.path == '/v1/refunds'"
    deny_if: "int(request.body.amount) > 50000"
```

10 production presets available out of the box in [`policies/presets/`](policies/presets/):
`stripe-safe.yaml`, `github-no-force-push.yaml`, `postgres-readonly.yaml`, `gmail-draft-only.yaml`, `aws-guard.yaml`, `slack-announce.yaml`, `bash-safe.yaml`, `filesystem-sandbox.yaml`, `database-crud-budget.yaml`, `browser-exec.yaml`.

---

## 🔍 Tamper-Evident Merkle Audit Ledger

Every tool call, policy decision, and human approval signature is cryptographically chained in local SQLite:

$$\text{record\_hash}_n = \text{SHA256}(\text{seq}_n \parallel \text{record\_hash}_{n-1} \parallel \text{timestamp} \parallel \text{agent\_id} \parallel \text{payload\_hash} \parallel \text{decision} \parallel \text{signature})$$

Verify chain integrity anytime:
```bash
./aegis verify
```
```text
✓ Cryptographic Audit Trail Verified (SOC-2/HIPAA Grade)
  Total Blocks: 42
  Tip Hash:     3a9f0e8d...4f2b
```

---

## 💻 SDKs

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

## ☁️ Optional Cloud & Multi-Tenant Deployment (`aegis-cloud`)

For production teams wanting hosted mobile passkeys and remote evaluation without running a local Go proxy binary:

```bash
docker run -d -p 8080:8080 \
  -e AEGIS_DATABASE_URL="libsql://your-db.turso.io?authToken=..." \
  -e AEGIS_RAPIDAPI_SECRET="your-rapidapi-secret" \
  -e AEGIS_UPGRADE_URL="https://polar.sh/augastinklazar" \
  --entrypoint "/usr/local/bin/aegis-cloud" \
  ghcr.io/augastinklazar/aegis:latest
```

* **`POST /v1/evaluate`**: Sub-5ms stateless guardrail evaluating proposed SQL, Bash commands, PII, and CEL policies.
* **`POST /v1/escalate`**: Hosted mobile approval relay for local agent proxies.
* **`GET /v1/audit/cloud`**: Multi-tenant compliance audit stream.

Connect local proxy to cloud relay:
```bash
./aegis login ag_live_your_polar_key_here
```

---

## 📄 License

MIT © [Augastin Lazar](https://github.com/augastinklazar) & Aegis Contributors. Free for local and commercial self-hosted usage.
