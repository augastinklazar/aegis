"""
Aegis Agent SDK
Zero-trust credentialless gateway & deterministic sandbox for AI agents.
"""

import time
import functools
import requests
from typing import Optional, Dict, Any

class AegisError(Exception):
    pass

class AegisDeniedError(AegisError):
    pass

class AegisClient:
    def __init__(self, base_url: str = "http://localhost:8080", token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def exchange_token(
        self,
        actor_token: str,
        subject_token: str,
        audience: str,
        scope: str = "",
        task_id: str = "",
        reason: str = "",
        ttl_seconds: int = 600,
        max_calls: int = 0,
    ) -> Dict[str, Any]:
        """Performs RFC 8693 Token Exchange with Aegis Broker."""
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "actor_token": actor_token,
            "subject_token": subject_token,
            "audience": audience,
            "scope": scope,
            "task_id": task_id,
            "reason": reason,
            "ttl_seconds": ttl_seconds,
            "max_calls": max_calls,
        }
        res = requests.post(f"{self.base_url}/v1/oauth/token", json=payload)
        if not res.ok:
            raise AegisError(f"Token exchange failed: {res.text}")
        data = res.json()
        self.token = data.get("access_token")
        return data

    def request(
        self,
        method: str,
        service: str,
        path: str,
        reason: str = "",
        poll_on_freeze: bool = True,
        **kwargs
    ) -> requests.Response:
        """Sends request through Aegis Gateway with phantom token and handles AAuth 202 async polling."""
        headers = kwargs.pop("headers", {})
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if reason:
            headers["X-Aegis-Reason"] = reason

        clean_path = path.lstrip("/")
        url = f"{self.base_url}/proxy/{service}/{clean_path}"

        res = requests.request(method, url, headers=headers, **kwargs)

        if res.status_code == 403:
            err_data = {}
            try:
                err_data = res.json()
            except Exception:
                pass
            msg = err_data.get("message") or err_data.get("error") or res.text
            raise AegisDeniedError(f"Action blocked by Aegis: {msg}")

        # Handle AAuth 202 Accepted polling if proxy responded with async handle
        if res.status_code == 202 and poll_on_freeze:
            data = res.json()
            poll_url = data.get("poll_endpoint")
            interval = data.get("interval", 2)
            timeout = data.get("expires_in", 300)

            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(interval)
                poll_res = requests.get(poll_url)
                if poll_res.ok:
                    status_data = poll_res.json()
                    st = status_data.get("status")
                    if st == "APPROVED":
                        # Resend original request
                        return requests.request(method, url, headers=headers, **kwargs)
                    elif st in ("DENIED", "TIMED_OUT"):
                        raise AegisDeniedError(f"Action {st} by human approver: {status_data.get('denial_reason')}")

            raise TimeoutError("Aegis approval polling timed out waiting for human sign-off")

        return res


def aegis_tool(service: str, client: Optional[AegisClient] = None, reason: str = ""):
    """
    Decorator for LangChain, CrewAI, or standalone tool functions.
    Ensures outbound calls are bound to Aegis security boundary.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Annotate context
            kwargs["_aegis_service"] = service
            if reason:
                kwargs["_aegis_reason"] = reason
            return fn(*args, **kwargs)
        return wrapper
    return decorator
