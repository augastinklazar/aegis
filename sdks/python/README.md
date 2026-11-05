# aegis-agent-sdk

Python client library for **Aegis** — zero-trust credential injection, deterministic sandbox, and human-in-the-loop escalation gateway for AI agents.

## Quickstart

```bash
pip install aegis-agent-sdk
```

```python
from aegis_agent_sdk import AegisClient

client = AegisClient("http://localhost:8080")

# 1. Exchange task-scoped phantom token (RFC 8693)
client.exchange_token(
    actor_token="refund-bot",
    subject_token="alice@company.com",
    audience="stripe_prod",
    task_id="refund_1234",
    reason="Customer refund request under policy limit"
)

# 2. Transparently call API (Aegis swaps phantom token for real decrypted Stripe key)
resp = client.request(
    method="POST",
    service="stripe_prod",
    path="/v1/refunds",
    json={"amount": 1500, "currency": "usd"},
    reason="Approved by user support request"
)

print(resp.json())
```
