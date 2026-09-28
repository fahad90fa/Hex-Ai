"""JWT Analyzer — test JWT tokens for common vulnerabilities."""
from __future__ import annotations

import base64
import json
import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.jwt_analyzer")


class JwtAnalyzerTool(BaseTool):
    name = "jwt_analyzer"
    category = ToolCategory.AUTH
    requires = []  # Pure Python implementation

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'token' required.")

        token: str = params["token"]
        secret: str = params.get("secret", "")
        target_url: str = params.get("target_url", "")
        timeout: int = int(params.get("timeout", 30))

        findings: list[Finding] = []
        output_lines: list[str] = []

        # Parse token
        parts = token.split(".")
        if len(parts) != 3:
            return ToolResult(success=False, error="Invalid JWT: must have 3 parts")

        header_b64, payload_b64, signature_b64 = parts

        try:
            header = json.loads(_b64_decode(header_b64))
            payload = json.loads(_b64_decode(payload_b64))
        except Exception as exc:
            return ToolResult(success=False, error=f"Failed to decode JWT: {exc}")

        output_lines.append(f"Header: {json.dumps(header, indent=2)}")
        output_lines.append(f"Payload: {json.dumps(payload, indent=2)}")

        # Check 1: None algorithm attack
        if header.get("alg", "").lower() == "none":
            findings.append(Finding(
                title="JWT None Algorithm Attack",
                severity=Severity.CRITICAL,
                description="JWT uses 'none' algorithm — no signature verification required!",
                affected_asset=target_url or "JWT token",
                evidence=f"alg: none",
                remediation="Reject JWTs with 'alg': 'none'. Enforce algorithm allowlist.",
            ))

        # Check 2: Weak algorithm
        alg = header.get("alg", "")
        weak_algs = {"HS256", "HS384", "HS512"}
        if alg in weak_algs:
            findings.append(Finding(
                title=f"JWT Uses Symmetric Algorithm: {alg}",
                severity=Severity.MEDIUM,
                description=f"JWT uses {alg} (symmetric). If the secret is weak, it can be brute-forced.",
                affected_asset=target_url or "JWT token",
                evidence=f"alg: {alg}",
                remediation="Use RS256/ES256 (asymmetric). Ensure secrets are cryptographically random (>=256 bits).",
            ))

        # Check 3: Algorithm confusion (RS256 → HS256)
        if alg.startswith("RS") or alg.startswith("ES"):
            output_lines.append("[CHECK] Algorithm confusion attack possible if public key is known")
            findings.append(Finding(
                title=f"JWT Algorithm Confusion Risk: {alg}",
                severity=Severity.HIGH,
                description=(
                    f"JWT uses asymmetric algorithm {alg}.\n"
                    f"If the server accepts HS256 with the public key as the secret, "
                    f"an algorithm confusion attack is possible."
                ),
                affected_asset=target_url or "JWT token",
                evidence=f"alg: {alg}",
                remediation="Enforce strict algorithm validation server-side.",
            ))

        # Check 4: Expiry
        exp = payload.get("exp")
        import time
        if exp is None:
            findings.append(Finding(
                title="JWT Has No Expiry (exp)",
                severity=Severity.MEDIUM,
                description="JWT does not have an 'exp' claim — tokens never expire.",
                affected_asset=target_url or "JWT token",
                evidence="exp: missing",
                remediation="Always set an expiry claim. Use short-lived tokens (15-60 minutes).",
            ))
        elif exp < time.time():
            findings.append(Finding(
                title="JWT Token is Expired",
                severity=Severity.INFO,
                description=f"JWT expired at {exp} (current time: {int(time.time())})",
                affected_asset=target_url or "JWT token",
                evidence=f"exp: {exp}",
            ))

        # Check 5: Sensitive data in payload
        sensitive_keys = {"password", "passwd", "secret", "private_key", "ssn", "credit_card"}
        for key in payload:
            if key.lower() in sensitive_keys:
                findings.append(Finding(
                    title=f"Sensitive Data in JWT Payload: {key}",
                    severity=Severity.HIGH,
                    description=f"JWT payload contains sensitive field '{key}'. JWT payload is base64-encoded (not encrypted).",
                    affected_asset=target_url or "JWT token",
                    evidence=f"Payload key: {key}",
                    remediation="Never store sensitive data in JWT payload. Use encrypted JWE if needed.",
                ))

        # Check 6: Brute force weak secret (if HS256)
        if secret and alg in weak_algs:
            try:
                import hmac
                import hashlib
                alg_map = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
                digest = hmac.new(
                    secret.encode(),
                    f"{header_b64}.{payload_b64}".encode(),
                    getattr(hashlib, alg_map[alg]),
                ).digest()
                expected_sig = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                if expected_sig == signature_b64:
                    findings.append(Finding(
                        title="JWT Secret Cracked",
                        severity=Severity.CRITICAL,
                        description=f"The provided secret '{secret}' correctly signs this JWT.",
                        affected_asset=target_url or "JWT token",
                        evidence=f"Secret matches: {secret}",
                        remediation="Change the JWT signing secret to a cryptographically random 256-bit value.",
                    ))
            except Exception:
                pass

        raw = "\n".join(output_lines)
        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        return []

    def validate_params(self, params: dict) -> bool:
        token = params.get("token", "")
        return bool(token) and token.count(".") == 2


def _b64_decode(data: str) -> bytes:
    """Base64url decode with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)
