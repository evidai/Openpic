"""
AuditLogger: Structured audit log for every agent request/response cycle.
Outputs JSON — compatible with any log aggregator (Datadog, Supabase, S3, etc.)
"""

from __future__ import annotations
import json
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Any

from ..input_guard.guard import InputScanReport
from ..output_guard.guard import OutputScanReport
from ..rule_of_two.engine import TaskPolicy


@dataclass
class AuditEntry:
    event_id: str
    timestamp: str
    tenant_id: str
    session_id: Optional[str]
    model_used: Optional[str]
    task_name: Optional[str]

    # Security results
    input_guard_result: str
    input_threat_count: int
    input_threat_types: list[str]

    output_guard_result: str
    output_leak_count: int
    output_leak_types: list[str]

    rule_of_two_status: str
    active_capabilities: list[str]

    # Performance
    latency_ms: Optional[float]

    # Optional metadata
    extra: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class AuditLogger:
    """
    Usage:
        logger = AuditLogger(tenant_id="client_abc", output="stdout")

        logger.log(
            input_report=input_scan,
            output_report=output_scan,
            policy=current_policy,
            model_used="claude-sonnet-4-6",
            latency_ms=142.3,
        )
    """

    def __init__(
        self,
        tenant_id: str,
        session_id: Optional[str] = None,
        output: str = "stdout",  # "stdout" | filepath
        extra_fields: Optional[dict] = None,
    ):
        self.tenant_id = tenant_id
        self.session_id = session_id or str(uuid.uuid4())
        self.output = output
        self.extra_fields = extra_fields or {}
        self._entries: list[AuditEntry] = []

        self._file = None
        if output not in ("stdout", "stderr"):
            self._file = open(output, "a", encoding="utf-8")

    def log(
        self,
        input_report: Optional[InputScanReport] = None,
        output_report: Optional[OutputScanReport] = None,
        policy: Optional[TaskPolicy] = None,
        model_used: Optional[str] = None,
        task_name: Optional[str] = None,
        latency_ms: Optional[float] = None,
        extra: Optional[dict] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            tenant_id=self.tenant_id,
            session_id=self.session_id,
            model_used=model_used,
            task_name=task_name or (policy.task_name if policy else None),

            input_guard_result=input_report.result.value if input_report else "skipped",
            input_threat_count=len(input_report.findings) if input_report else 0,
            input_threat_types=list({f.threat_type.value for f in input_report.findings}) if input_report else [],

            output_guard_result=output_report.result.value if output_report else "skipped",
            output_leak_count=len(output_report.findings) if output_report else 0,
            output_leak_types=list({f.leak_type.value for f in output_report.findings}) if output_report else [],

            rule_of_two_status="safe" if (policy and policy.is_safe) else ("violation" if policy else "skipped"),
            active_capabilities=policy.active_capabilities() if policy else [],

            latency_ms=round(latency_ms, 2) if latency_ms else None,
            extra={**self.extra_fields, **(extra or {})},
        )

        self._entries.append(entry)
        self._write(entry)
        return entry

    def _write(self, entry: AuditEntry) -> None:
        line = entry.to_json()
        if self.output == "stdout":
            print(line, flush=True)
        elif self.output == "stderr":
            print(line, file=sys.stderr, flush=True)
        else:
            self._file.write(line + "\n")
            self._file.flush()

    def get_entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def summary(self) -> dict[str, Any]:
        total = len(self._entries)
        blocked = sum(1 for e in self._entries if e.input_guard_result == "blocked")
        leaks_caught = sum(e.output_leak_count for e in self._entries)
        violations = sum(1 for e in self._entries if e.rule_of_two_status == "violation")
        return {
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "total_requests": total,
            "input_blocked": blocked,
            "output_leaks_caught": leaks_caught,
            "rule_of_two_violations": violations,
        }

    def __del__(self):
        if self._file:
            self._file.close()
