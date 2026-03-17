"""
secure-agent-core REST API
Wrap any AI agent pipeline with HTTP endpoints.
Enables multi-tenant SaaS usage.
"""

from __future__ import annotations
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

from src.input_guard.guard import InputGuard
from src.output_guard.guard import OutputGuard
from src.rule_of_two.engine import RuleOfTwo, PolicyViolationError
from src.audit_log.logger import AuditLogger

app = FastAPI(
    title="secure-agent-core",
    description="Model-agnostic AI agent security layer",
    version="0.1.0",
)

# ── In-memory tenant registry (replace with DB in production) ───────────────
_loggers: dict[str, AuditLogger] = {}

def _get_logger(tenant_id: str) -> AuditLogger:
    if tenant_id not in _loggers:
        _loggers[tenant_id] = AuditLogger(
            tenant_id=tenant_id,
            output="stdout",
        )
    return _loggers[tenant_id]


# ── Request / Response schemas ───────────────────────────────────────────────

class ScanInputRequest(BaseModel):
    user_message: str
    external_data: Optional[str] = None
    context_type: str = "general"
    block_on_critical: bool = True

class ScanInputResponse(BaseModel):
    result: str
    is_safe: bool
    cleaned_input: Optional[str]
    external_data_cleaned: Optional[str]
    threat_count: int
    threats: list[dict]

class ScanOutputRequest(BaseModel):
    output: str
    block_on_critical: bool = False

class ScanOutputResponse(BaseModel):
    result: str
    is_safe: bool
    safe_output: str
    leak_count: int
    leaks: list[dict]

class ValidatePolicyRequest(BaseModel):
    task_name: Optional[str] = None
    access_confidential_db: bool = False
    external_network: bool = False
    read_untrusted_content: bool = False

class ValidatePolicyResponse(BaseModel):
    is_safe: bool
    active_capabilities: list[str]
    description: str

class FullPipelineRequest(BaseModel):
    user_message: str
    external_data: Optional[str] = None
    context_type: str = "general"
    agent_output: str
    task_name: Optional[str] = None
    access_confidential_db: bool = False
    external_network: bool = False
    read_untrusted_content: bool = False
    model_used: Optional[str] = None

class AuditSummaryResponse(BaseModel):
    tenant_id: str
    session_id: str
    total_requests: int
    input_blocked: int
    output_leaks_caught: int
    rule_of_two_violations: int


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/v1/scan/input", response_model=ScanInputResponse)
def scan_input(
    req: ScanInputRequest,
    x_tenant_id: str = Header(default="default"),
):
    t0 = time.time()
    guard = InputGuard(block_on_critical=req.block_on_critical)
    report = guard.scan(
        user_message=req.user_message,
        external_data=req.external_data,
        context_type=req.context_type,
    )
    latency = (time.time() - t0) * 1000

    logger = _get_logger(x_tenant_id)
    logger.log(input_report=report, latency_ms=latency)

    return ScanInputResponse(
        result=report.result.value,
        is_safe=report.is_safe,
        cleaned_input=report.cleaned_input,
        external_data_cleaned=report.external_data_cleaned,
        threat_count=len(report.findings),
        threats=[
            {
                "type": f.threat_type.value,
                "severity": f.severity,
                "location": f.location,
                "auto_cleaned": f.auto_cleaned,
            }
            for f in report.findings
        ],
    )


@app.post("/v1/scan/output", response_model=ScanOutputResponse)
def scan_output(
    req: ScanOutputRequest,
    x_tenant_id: str = Header(default="default"),
):
    t0 = time.time()
    guard = OutputGuard(block_on_critical=req.block_on_critical)
    report = guard.scan(req.output)
    latency = (time.time() - t0) * 1000

    logger = _get_logger(x_tenant_id)
    logger.log(output_report=report, latency_ms=latency)

    return ScanOutputResponse(
        result=report.result.value,
        is_safe=report.is_safe,
        safe_output=report.safe_output,
        leak_count=len(report.findings),
        leaks=[
            {
                "type": f.leak_type.value,
                "severity": f.severity,
                "count": f.count,
            }
            for f in report.findings
        ],
    )


@app.post("/v1/policy/validate", response_model=ValidatePolicyResponse)
def validate_policy(
    req: ValidatePolicyRequest,
    x_tenant_id: str = Header(default="default"),
):
    engine = RuleOfTwo()
    policy = engine.set_task(
        task_name=req.task_name,
        access_confidential_db=req.access_confidential_db,
        external_network=req.external_network,
        read_untrusted_content=req.read_untrusted_content,
    )
    return ValidatePolicyResponse(
        is_safe=policy.is_safe,
        active_capabilities=policy.active_capabilities(),
        description=engine.describe(),
    )


@app.post("/v1/pipeline/full")
def full_pipeline(
    req: FullPipelineRequest,
    x_tenant_id: str = Header(default="default"),
):
    """
    One-shot endpoint: validate policy → scan input → [run your agent] → scan output.
    In production, the agent call happens client-side between /scan/input and /scan/output.
    This endpoint simulates the full flow for testing.
    """
    t0 = time.time()

    # Step 1: Policy check
    engine = RuleOfTwo()
    policy = engine.set_task(
        task_name=req.task_name,
        access_confidential_db=req.access_confidential_db,
        external_network=req.external_network,
        read_untrusted_content=req.read_untrusted_content,
    )
    try:
        policy.validate()
    except PolicyViolationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Step 2: Input scan
    input_guard = InputGuard()
    input_report = input_guard.scan(
        user_message=req.user_message,
        external_data=req.external_data,
        context_type=req.context_type,
    )
    if not input_report.is_safe:
        raise HTTPException(
            status_code=400,
            detail=f"Input blocked: {input_report.blocked_reason}",
        )

    # Step 3: Output scan
    output_guard = OutputGuard()
    output_report = output_guard.scan(req.agent_output)

    latency = (time.time() - t0) * 1000

    # Step 4: Audit log
    logger = _get_logger(x_tenant_id)
    logger.log(
        input_report=input_report,
        output_report=output_report,
        policy=policy,
        model_used=req.model_used,
        task_name=req.task_name,
        latency_ms=latency,
    )

    return {
        "policy": {"is_safe": policy.is_safe, "active": policy.active_capabilities()},
        "input": {"result": input_report.result.value, "threat_count": len(input_report.findings)},
        "output": {"result": output_report.result.value, "safe_output": output_report.safe_output},
        "latency_ms": round(latency, 2),
    }


@app.get("/v1/audit/summary", response_model=AuditSummaryResponse)
def audit_summary(x_tenant_id: str = Header(default="default")):
    logger = _get_logger(x_tenant_id)
    s = logger.summary()
    return AuditSummaryResponse(**s)
