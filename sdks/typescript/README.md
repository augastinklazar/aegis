# @aegis-auth/sdk

TypeScript / JavaScript SDK and MCP middleware for **Aegis** — zero-trust credential injection, deterministic sandbox, and human-in-the-loop escalation gateway for AI agents.

## Install

```bash
npm install @aegis-auth/sdk
```

## Usage

```typescript
import { AegisClient } from "@aegis-auth/sdk";

const aegis = new AegisClient({
  baseUrl: "http://localhost:8080",
});

// 1. Exchange task-scoped phantom token (RFC 8693)
const { accessToken } = await aegis.exchangeToken({
  actorToken: "invoice-bot",
  subjectToken: "finance-admin@org.com",
  audience: "stripe_prod",
  maxCalls: 10,
  reason: "Reconcile duplicate charges"
});

// 2. Wrap standard fetch to automatically route through Aegis
const secureFetch = aegis.createFetch("stripe_prod");

const response = await secureFetch("/v1/refunds", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ amount: 1500, currency: "usd" }),
});

console.log(await response.json());
```
