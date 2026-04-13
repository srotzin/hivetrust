"""
hivetrust
~~~~~~~~~

Official Python SDK for the HiveTrust API — KYA Identity Verification,
Trust Scoring & Parametric Insurance for AI Agents.

Synchronous usage (httpx):
    from hivetrust import HiveTrustClient

    trust = HiveTrustClient("https://hivetrust.hiveagentiq.com", "ht_your_api_key")
    score = trust.get_trust_score("agent-uuid")
    print(score["score"], score["tier"])

Async usage:
    from hivetrust import AsyncHiveTrustClient
    import asyncio

    async def main():
        async with AsyncHiveTrustClient("https://hivetrust.hiveagentiq.com", "ht_your_api_key") as trust:
            score = await trust.get_trust_score("agent-uuid")
            print(score["score"])

    asyncio.run(main())
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

__version__ = "1.0.0"
__all__ = ["HiveTrustClient", "AsyncHiveTrustClient", "HiveTrustError"]

SDK_VERSION = __version__


class HiveTrustError(Exception):
    """Raised when the HiveTrust API returns a non-2xx response."""

    def __init__(self, message: str, status_code: int, body: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _extract_error_message(body: Any) -> str:
    if isinstance(body, dict):
        return body.get("message") or body.get("error") or str(body)
    return str(body)


# ─────────────────────────────────────────────────────────────────────────────
# Synchronous client
# ─────────────────────────────────────────────────────────────────────────────

class HiveTrustClient:
    """
    Synchronous HiveTrust API client.

    Parameters
    ----------
    base_url:
        Base URL of the HiveTrust instance (e.g. https://hivetrust.hiveagentiq.com).
    api_key:
        Your HiveTrust API key.
    timeout:
        Default request timeout in seconds (default: 30).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 30.0,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        if not api_key:
            raise ValueError("api_key is required")

        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "X-API-Key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"hivetrust-python/{SDK_VERSION}",
            },
            timeout=timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> "HiveTrustClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ── Private helper ────────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict] = None,
    ) -> Any:
        res = self._client.request(method, path, json=json, params=params)
        try:
            body = res.json()
        except Exception:
            body = res.text

        if res.is_error:
            raise HiveTrustError(
                _extract_error_message(body),
                status_code=res.status_code,
                body=body,
            )
        return body

    # ── Identity (KYA) ────────────────────────────────────────────────────────

    def register_agent(self, agent_data: dict) -> dict:
        """Register a new agent identity. Cost: $0.01."""
        return self._request("POST", "/v1/agents", json=agent_data)

    def get_agent(self, agent_id: str) -> dict:
        """Retrieve an agent's full profile."""
        return self._request("GET", f"/v1/agents/{agent_id}")

    def update_agent(self, agent_id: str, updates: dict) -> dict:
        """Update agent metadata (creates an immutable version snapshot). Cost: $0.01."""
        return self._request("PUT", f"/v1/agents/{agent_id}", json=updates)

    def deactivate_agent(self, agent_id: str) -> dict:
        """Deactivate an agent and add it to the revocation registry."""
        return self._request("DELETE", f"/v1/agents/{agent_id}")

    # ── Trust Score ───────────────────────────────────────────────────────────

    def get_trust_score(self, agent_id: str) -> dict:
        """Get the current composite trust score and pillar breakdown. Cost: $0.01."""
        return self._request("GET", f"/v1/agents/{agent_id}/score")

    def get_trust_score_history(
        self,
        agent_id: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """Get paginated score history."""
        return self._request(
            "GET",
            f"/v1/agents/{agent_id}/score/history",
            params={"limit": limit, "offset": offset},
        )

    def verify_agent_risk(
        self,
        agent_id: str,
        *,
        min_score: Optional[int] = None,
    ) -> dict:
        """
        Fast binary risk check — returns ``clear`` or ``block`` in < 50ms.
        Ideal for payment-processor pre-authorisation gates. Cost: $0.01.
        """
        params: dict = {"agent_id": agent_id}
        if min_score is not None:
            params["min_score"] = min_score
        return self._request("GET", "/v1/verify_agent_risk", params=params)

    # ── Telemetry ─────────────────────────────────────────────────────────────

    def ingest_telemetry(self, events: dict) -> dict:
        """
        Bulk-ingest behavioural events (up to 1 000 per call).
        Cost: $0.001/event.
        """
        return self._request("POST", "/v1/telemetry/ingest", json=events)

    def get_agent_events(
        self,
        agent_id: str,
        *,
        limit: int = 20,
        offset: int = 0,
        event_type: Optional[str] = None,
    ) -> dict:
        """Query the full audit trail for an agent."""
        params: dict = {"limit": limit, "offset": offset}
        if event_type:
            params["event_type"] = event_type
        return self._request("GET", f"/v1/agents/{agent_id}/events", params=params)

    # ── Credentials ───────────────────────────────────────────────────────────

    def issue_credential(
        self,
        agent_id: str,
        credential_type: str,
        issuer_id: str,
        claims: Optional[dict] = None,
        *,
        ttl_days: Optional[int] = None,
    ) -> dict:
        """Issue a W3C Verifiable Credential to an agent. Cost: $0.05."""
        body: dict = {
            "credential_type": credential_type,
            "issuer_id": issuer_id,
            "claims": claims or {},
        }
        if ttl_days is not None:
            body["ttl_days"] = ttl_days
        return self._request("POST", f"/v1/agents/{agent_id}/credentials", json=body)

    def list_credentials(
        self,
        agent_id: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List all credentials for an agent."""
        return self._request(
            "GET",
            f"/v1/agents/{agent_id}/credentials",
            params={"limit": limit, "offset": offset},
        )

    def revoke_credential(
        self,
        agent_id: str,
        credential_id: str,
        *,
        reason: Optional[str] = None,
    ) -> dict:
        """Revoke a credential."""
        body = {"reason": reason} if reason else {}
        return self._request(
            "DELETE",
            f"/v1/agents/{agent_id}/credentials/{credential_id}",
            json=body,
        )

    def verify_credential(self, credential_id: str) -> dict:
        """Verify a presented credential (signature + expiry + revocation). Cost: $0.01."""
        return self._request(
            "POST", "/v1/verify/credential", json={"credential_id": credential_id}
        )

    # ── Insurance ─────────────────────────────────────────────────────────────

    def get_insurance_quote(
        self,
        agent_id: str,
        counterparty_id: Optional[str],
        transaction_value_usdc: float,
        *,
        policy_type: str = "transaction",
    ) -> dict:
        """Get a dynamic insurance premium quote."""
        body: dict = {
            "agent_id": agent_id,
            "transaction_value_usdc": transaction_value_usdc,
            "policy_type": policy_type,
        }
        if counterparty_id:
            body["counterparty_id"] = counterparty_id
        return self._request("POST", "/v1/insurance/quote", json=body)

    def bind_insurance(
        self,
        agent_id: str,
        quote_details: dict,
        transaction_value_usdc: float,
    ) -> dict:
        """Bind a policy and deploy USDC escrow on Base L2. Take rate: 1.5%."""
        body = {
            "agent_id": agent_id,
            "transaction_value_usdc": transaction_value_usdc,
            **quote_details,
        }
        return self._request("POST", "/v1/insurance/bind", json=body)

    def get_insurance_policy(self, policy_id: str) -> dict:
        """Retrieve a policy by ID."""
        return self._request("GET", f"/v1/insurance/policies/{policy_id}")

    def file_claim(self, claim_data: dict) -> dict:
        """File a parametric insurance claim."""
        return self._request("POST", "/v1/insurance/claims", json=claim_data)

    def get_claim(self, claim_id: str) -> dict:
        """Get claim status."""
        return self._request("GET", f"/v1/insurance/claims/{claim_id}")

    # ── Disputes ──────────────────────────────────────────────────────────────

    def file_dispute(self, dispute_data: dict) -> dict:
        """File a dispute against a counterparty agent."""
        return self._request("POST", "/v1/disputes", json=dispute_data)

    def get_dispute(self, dispute_id: str) -> dict:
        """Get dispute details."""
        return self._request("GET", f"/v1/disputes/{dispute_id}")

    def resolve_dispute(
        self,
        dispute_id: str,
        outcome: str,
        *,
        resolution_notes: Optional[str] = None,
    ) -> dict:
        """Submit a dispute resolution."""
        body: dict = {"outcome": outcome}
        if resolution_notes:
            body["resolution_notes"] = resolution_notes
        return self._request("POST", f"/v1/disputes/{dispute_id}/resolve", json=body)

    # ── Webhooks ──────────────────────────────────────────────────────────────

    def register_webhook(self, url: str, events: list[str]) -> dict:
        """Register a webhook endpoint (HMAC-SHA256 signed)."""
        return self._request("POST", "/v1/webhooks", json={"url": url, "events": events})

    def list_webhooks(self) -> dict:
        """List all registered webhooks."""
        return self._request("GET", "/v1/webhooks")

    def delete_webhook(self, webhook_id: str) -> dict:
        """Remove a webhook."""
        return self._request("DELETE", f"/v1/webhooks/{webhook_id}")

    # ── Federation ────────────────────────────────────────────────────────────

    def register_federation_peer(self, name: str, base_url: str) -> dict:
        """Register a HiveTrust-compatible federation peer."""
        return self._request("POST", "/v1/federation/peers", json={"name": name, "base_url": base_url})

    def list_federation_peers(self) -> dict:
        """List federated peer registries."""
        return self._request("GET", "/v1/federation/peers")

    def sync_federation(self, peer_id: str) -> dict:
        """Initiate bidirectional score sync with a peer."""
        return self._request("POST", "/v1/federation/sync", json={"peer_id": peer_id})

    # ── System ────────────────────────────────────────────────────────────────

    def health(self) -> dict:
        """Health check (no authentication required)."""
        res = httpx.get(f"{self._base_url}/health", headers={"Accept": "application/json"})
        return res.json()

    def get_platform_stats(self) -> dict:
        """Get platform-wide statistics."""
        return self._request("GET", "/v1/stats")

    def get_discovery(self) -> dict:
        """Get the platform discovery document."""
        res = httpx.get(
            f"{self._base_url}/.well-known/hivetrust.json",
            headers={"Accept": "application/json"},
        )
        return res.json()


# ─────────────────────────────────────────────────────────────────────────────
# Async client
# ─────────────────────────────────────────────────────────────────────────────

class AsyncHiveTrustClient:
    """
    Asynchronous HiveTrust API client (uses httpx.AsyncClient).

    Parameters
    ----------
    base_url:
        Base URL of the HiveTrust instance.
    api_key:
        Your HiveTrust API key.
    timeout:
        Default request timeout in seconds (default: 30).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 30.0,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        if not api_key:
            raise ValueError("api_key is required")

        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "X-API-Key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"hivetrust-python/{SDK_VERSION} async",
            },
            timeout=timeout,
        )

    async def aclose(self) -> None:
        """Close the underlying async HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncHiveTrustClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    # ── Private helper ────────────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict] = None,
    ) -> Any:
        res = await self._client.request(method, path, json=json, params=params)
        try:
            body = res.json()
        except Exception:
            body = res.text

        if res.is_error:
            raise HiveTrustError(
                _extract_error_message(body),
                status_code=res.status_code,
                body=body,
            )
        return body

    # ── Identity (KYA) ────────────────────────────────────────────────────────

    async def register_agent(self, agent_data: dict) -> dict:
        return await self._request("POST", "/v1/agents", json=agent_data)

    async def get_agent(self, agent_id: str) -> dict:
        return await self._request("GET", f"/v1/agents/{agent_id}")

    async def update_agent(self, agent_id: str, updates: dict) -> dict:
        return await self._request("PUT", f"/v1/agents/{agent_id}", json=updates)

    async def deactivate_agent(self, agent_id: str) -> dict:
        return await self._request("DELETE", f"/v1/agents/{agent_id}")

    # ── Trust Score ───────────────────────────────────────────────────────────

    async def get_trust_score(self, agent_id: str) -> dict:
        return await self._request("GET", f"/v1/agents/{agent_id}/score")

    async def get_trust_score_history(
        self,
        agent_id: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        return await self._request(
            "GET",
            f"/v1/agents/{agent_id}/score/history",
            params={"limit": limit, "offset": offset},
        )

    async def verify_agent_risk(
        self,
        agent_id: str,
        *,
        min_score: Optional[int] = None,
    ) -> dict:
        params: dict = {"agent_id": agent_id}
        if min_score is not None:
            params["min_score"] = min_score
        return await self._request("GET", "/v1/verify_agent_risk", params=params)

    # ── Telemetry ─────────────────────────────────────────────────────────────

    async def ingest_telemetry(self, events: dict) -> dict:
        return await self._request("POST", "/v1/telemetry/ingest", json=events)

    async def get_agent_events(
        self,
        agent_id: str,
        *,
        limit: int = 20,
        offset: int = 0,
        event_type: Optional[str] = None,
    ) -> dict:
        params: dict = {"limit": limit, "offset": offset}
        if event_type:
            params["event_type"] = event_type
        return await self._request("GET", f"/v1/agents/{agent_id}/events", params=params)

    # ── Credentials ───────────────────────────────────────────────────────────

    async def issue_credential(
        self,
        agent_id: str,
        credential_type: str,
        issuer_id: str,
        claims: Optional[dict] = None,
        *,
        ttl_days: Optional[int] = None,
    ) -> dict:
        body: dict = {
            "credential_type": credential_type,
            "issuer_id": issuer_id,
            "claims": claims or {},
        }
        if ttl_days is not None:
            body["ttl_days"] = ttl_days
        return await self._request("POST", f"/v1/agents/{agent_id}/credentials", json=body)

    async def list_credentials(
        self,
        agent_id: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        return await self._request(
            "GET",
            f"/v1/agents/{agent_id}/credentials",
            params={"limit": limit, "offset": offset},
        )

    async def revoke_credential(
        self,
        agent_id: str,
        credential_id: str,
        *,
        reason: Optional[str] = None,
    ) -> dict:
        body = {"reason": reason} if reason else {}
        return await self._request(
            "DELETE",
            f"/v1/agents/{agent_id}/credentials/{credential_id}",
            json=body,
        )

    async def verify_credential(self, credential_id: str) -> dict:
        return await self._request(
            "POST", "/v1/verify/credential", json={"credential_id": credential_id}
        )

    # ── Insurance ─────────────────────────────────────────────────────────────

    async def get_insurance_quote(
        self,
        agent_id: str,
        counterparty_id: Optional[str],
        transaction_value_usdc: float,
        *,
        policy_type: str = "transaction",
    ) -> dict:
        body: dict = {
            "agent_id": agent_id,
            "transaction_value_usdc": transaction_value_usdc,
            "policy_type": policy_type,
        }
        if counterparty_id:
            body["counterparty_id"] = counterparty_id
        return await self._request("POST", "/v1/insurance/quote", json=body)

    async def bind_insurance(
        self,
        agent_id: str,
        quote_details: dict,
        transaction_value_usdc: float,
    ) -> dict:
        body = {
            "agent_id": agent_id,
            "transaction_value_usdc": transaction_value_usdc,
            **quote_details,
        }
        return await self._request("POST", "/v1/insurance/bind", json=body)

    async def get_insurance_policy(self, policy_id: str) -> dict:
        return await self._request("GET", f"/v1/insurance/policies/{policy_id}")

    async def file_claim(self, claim_data: dict) -> dict:
        return await self._request("POST", "/v1/insurance/claims", json=claim_data)

    async def get_claim(self, claim_id: str) -> dict:
        return await self._request("GET", f"/v1/insurance/claims/{claim_id}")

    # ── Disputes ──────────────────────────────────────────────────────────────

    async def file_dispute(self, dispute_data: dict) -> dict:
        return await self._request("POST", "/v1/disputes", json=dispute_data)

    async def get_dispute(self, dispute_id: str) -> dict:
        return await self._request("GET", f"/v1/disputes/{dispute_id}")

    async def resolve_dispute(
        self,
        dispute_id: str,
        outcome: str,
        *,
        resolution_notes: Optional[str] = None,
    ) -> dict:
        body: dict = {"outcome": outcome}
        if resolution_notes:
            body["resolution_notes"] = resolution_notes
        return await self._request("POST", f"/v1/disputes/{dispute_id}/resolve", json=body)

    # ── Webhooks ──────────────────────────────────────────────────────────────

    async def register_webhook(self, url: str, events: list[str]) -> dict:
        return await self._request("POST", "/v1/webhooks", json={"url": url, "events": events})

    async def list_webhooks(self) -> dict:
        return await self._request("GET", "/v1/webhooks")

    async def delete_webhook(self, webhook_id: str) -> dict:
        return await self._request("DELETE", f"/v1/webhooks/{webhook_id}")

    # ── Federation ────────────────────────────────────────────────────────────

    async def register_federation_peer(self, name: str, base_url: str) -> dict:
        return await self._request(
            "POST", "/v1/federation/peers", json={"name": name, "base_url": base_url}
        )

    async def list_federation_peers(self) -> dict:
        return await self._request("GET", "/v1/federation/peers")

    async def sync_federation(self, peer_id: str) -> dict:
        return await self._request("POST", "/v1/federation/sync", json={"peer_id": peer_id})

    # ── System ────────────────────────────────────────────────────────────────

    async def health(self) -> dict:
        async with httpx.AsyncClient() as client:
            res = await client.get(
                f"{self._base_url}/health",
                headers={"Accept": "application/json"},
            )
            return res.json()

    async def get_platform_stats(self) -> dict:
        return await self._request("GET", "/v1/stats")

    async def get_discovery(self) -> dict:
        async with httpx.AsyncClient() as client:
            res = await client.get(
                f"{self._base_url}/.well-known/hivetrust.json",
                headers={"Accept": "application/json"},
            )
            return res.json()
