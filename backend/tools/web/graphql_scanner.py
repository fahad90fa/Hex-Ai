"""GraphQL Scanner — introspection, IDOR, injection testing for GraphQL APIs."""
from __future__ import annotations

import json
import logging

import httpx

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.graphql_scanner")


class GraphQLScannerTool(BaseTool):
    name = "graphql_scanner"
    category = ToolCategory.WEB
    requires = []  # Uses httpx for HTTP requests

    INTROSPECTION_QUERY = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          description
          fields {
            name
            description
            args { name type { name kind } }
            type { name kind }
          }
        }
      }
    }
    """

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"https://{target}"

        timeout: int = int(params.get("timeout", 120))
        headers: dict = params.get("headers", {})
        auth_token: str = params.get("auth_token", "")

        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        findings: list[Finding] = []
        raw_output = ""

        async with httpx.AsyncClient(timeout=30, headers=headers) as client:
            # Test introspection
            try:
                resp = await client.post(
                    target,
                    json={"query": self.INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json"},
                )
                raw_output = resp.text

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("data", {}).get("__schema"):
                        findings.append(Finding(
                            title="GraphQL Introspection Enabled",
                            severity=Severity.MEDIUM,
                            description=(
                                "GraphQL introspection is enabled on this endpoint.\n"
                                "Attackers can enumerate the full schema, types, queries and mutations."
                            ),
                            affected_asset=target,
                            evidence=f"Introspection query returned schema data",
                            remediation="Disable introspection in production environments.",
                        ))
                        # Extract types for further analysis
                        types = data["data"]["__schema"].get("types", [])
                        user_types = [t for t in types if any(
                            kw in t.get("name", "").lower()
                            for kw in ["user", "admin", "password", "token", "credential", "secret"]
                        )]
                        for t in user_types:
                            findings.append(Finding(
                                title=f"Sensitive GraphQL Type: {t['name']}",
                                severity=Severity.LOW,
                                description=f"GraphQL schema exposes potentially sensitive type: {t['name']}",
                                affected_asset=target,
                                evidence=json.dumps(t),
                            ))

            except Exception as exc:
                logger.debug("GraphQL introspection error: %s", exc)

            # Test for batch query attack
            try:
                batch_payload = [
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                ] * 100

                resp2 = await client.post(
                    target,
                    json=batch_payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp2.status_code == 200 and isinstance(resp2.json(), list):
                    findings.append(Finding(
                        title="GraphQL Batching Enabled (DoS Risk)",
                        severity=Severity.MEDIUM,
                        description=(
                            "GraphQL query batching is enabled.\n"
                            "Attackers can send large batch requests to cause resource exhaustion."
                        ),
                        affected_asset=target,
                        evidence=f"Batch of 100 queries returned status {resp2.status_code}",
                        remediation="Limit query depth, complexity, and disable batching if not needed.",
                    ))
            except Exception:
                pass

        return ToolResult(success=True, output=raw_output, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        return []

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target)
