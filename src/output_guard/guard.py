"""
OutputGuard: Scan LLM output for PII, API keys, and sensitive data
before returning to the end user or external systems.
Model-agnostic — works on any text output from any LLM.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class OutputScanResult(str, Enum):
    CLEAN = "clean"
    REDACTED = "redacted"
    BLOCKED = "blocked"


class LeakType(str, Enum):
    EMAIL = "email"
    PHONE_JP = "phone_jp"
    PHONE_INTL = "phone_intl"
    API_KEY = "api_key"
    AWS_KEY = "aws_key"
    CREDIT_CARD = "credit_card"
    JP_MYNUMBER = "jp_mynumber"
    JWT_TOKEN = "jwt_token"
    PRIVATE_KEY = "private_key"
    IP_ADDRESS = "ip_address"
    PASSWORD_LITERAL = "password_literal"


@dataclass
class LeakFinding:
    leak_type: LeakType
    severity: str
    redacted_sample: str  # Show only masked version, never raw value
    count: int = 1


@dataclass
class OutputScanReport:
    result: OutputScanResult
    original_output: str
    safe_output: str  # redacted version — always use this
    findings: list[LeakFinding] = field(default_factory=list)
    blocked_reason: Optional[str] = None

    @property
    def is_safe(self) -> bool:
        return self.result != OutputScanResult.BLOCKED


# ── Detection patterns ───────────────────────────────────────────────────────

LEAK_PATTERNS: list[tuple[LeakType, str, str, str]] = [
    # (type, pattern, severity, redact_replacement)

    # API Keys
    (LeakType.API_KEY,
     r"sk-[a-zA-Z0-9]{20,}",
     "critical", "sk-[REDACTED]"),
    (LeakType.API_KEY,
     r"Bearer\s+[a-zA-Z0-9\-._~+/]{20,}",
     "critical", "Bearer [REDACTED]"),
    (LeakType.AWS_KEY,
     r"AKIA[0-9A-Z]{16}",
     "critical", "AKIA[REDACTED]"),
    (LeakType.AWS_KEY,
     r"(?:aws_secret_access_key|AWS_SECRET)[\"'\s:=]+[a-zA-Z0-9/+]{40}",
     "critical", "[AWS_SECRET REDACTED]"),

    # Tokens
    (LeakType.JWT_TOKEN,
     r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
     "critical", "[JWT REDACTED]"),
    (LeakType.PRIVATE_KEY,
     r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "critical", "[PRIVATE KEY REDACTED]"),

    # Credit card BEFORE mynumber (longer pattern takes priority)
    (LeakType.CREDIT_CARD,
     r"\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}|\b\d{16}\b",
     "critical", "[CARD REDACTED]"),

    # PII — Japan specific
    (LeakType.JP_MYNUMBER,
     r"(?<!\d)\d{4}[\s\-]\d{4}[\s\-]\d{4}(?!\s*\d{4})(?!\d)",
     "high", "[MYNUMBER REDACTED]"),
    (LeakType.PHONE_JP,
     r"0\d{1,4}[\s\-]\d{1,4}[\s\-]\d{4}",
     "high", "[PHONE REDACTED]"),

    # PII — General
    (LeakType.EMAIL,
     r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
     "medium", "[EMAIL REDACTED]"),
    (LeakType.PHONE_INTL,
     r"\+\d{1,3}[\s\-]\d{1,4}[\s\-]\d{3,4}[\s\-]\d{4}",
     "medium", "[PHONE REDACTED]"),

    # Infrastructure
    (LeakType.IP_ADDRESS,
     r"\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b",
     "medium", "[INTERNAL IP REDACTED]"),

    # Literal password patterns
    (LeakType.PASSWORD_LITERAL,
     r"(?:password|passwd|pwd|secret)\s*[=:\"']+\s*\S{6,}",
     "critical", "[PASSWORD REDACTED]"),
]


class OutputGuard:
    """
    Model-agnostic output scanner. Insert after any LLM response.

    Usage:
        guard = OutputGuard()
        report = guard.scan(llm_response_text)
        return_to_user(report.safe_output)
    """

    def __init__(
        self,
        scan_for: Optional[list[str]] = None,
        block_on_critical: bool = False,
        redact_all: bool = True,
        allowlist_emails: Optional[list[str]] = None,
    ):
        self.scan_for = scan_for or [t.value for t in LeakType]
        self.block_on_critical = block_on_critical
        self.redact_all = redact_all
        self.allowlist_emails = [e.lower() for e in (allowlist_emails or [])]

    def scan(self, output: str) -> OutputScanReport:
        findings: list[LeakFinding] = []
        safe_output = output

        for leak_type, pattern, severity, replacement in LEAK_PATTERNS:
            if leak_type.value not in self.scan_for:
                continue

            matches = list(re.finditer(pattern, safe_output, re.IGNORECASE))
            if not matches:
                continue

            # Email allowlist check — only non-allowlisted matches matter
            if leak_type == LeakType.EMAIL and self.allowlist_emails:
                matches = [
                    m for m in matches
                    if m.group().lower() not in self.allowlist_emails
                ]
            if not matches:
                continue

            findings.append(LeakFinding(
                leak_type=leak_type,
                severity=severity,
                redacted_sample=replacement,
                count=len(matches),
            ))

            if self.redact_all:
                if leak_type == LeakType.EMAIL and self.allowlist_emails:
                    # Redact only non-allowlisted emails
                    def redact_if_not_allowed(m):
                        return m.group() if m.group().lower() in self.allowlist_emails else replacement
                    safe_output = re.sub(pattern, redact_if_not_allowed, safe_output, flags=re.IGNORECASE)
                else:
                    safe_output = re.sub(
                        pattern, replacement, safe_output, flags=re.IGNORECASE
                    )

        # Determine result
        if self.block_on_critical and any(f.severity == "critical" for f in findings):
            return OutputScanReport(
                result=OutputScanResult.BLOCKED,
                original_output=output,
                safe_output="[Output blocked due to sensitive data detection]",
                findings=findings,
                blocked_reason="Critical data detected in output.",
            )

        result = OutputScanResult.REDACTED if findings else OutputScanResult.CLEAN
        return OutputScanReport(
            result=result,
            original_output=output,
            safe_output=safe_output,
            findings=findings,
        )
