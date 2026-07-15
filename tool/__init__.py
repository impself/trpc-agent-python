"""Top-level package for the standalone Tool Script Safety Guard reference.

This package is deliberately self-contained. It must not import from
``trpc_agent_sdk`` so that it can be reused, audited, and tested in isolation.
The framework integration points (Tool Filter, CodeExecutor wrapper) consume
the public surface exported here without modifying existing SDK files.
"""

from tool.safety._exceptions import (
    SafetyAuditError,
    SafetyPolicyError,
    SafetyGuardError,
    SafetyScannerError,
)
from tool.safety._models import (
    Evidence,
    RiskCategory,
    RiskLevel,
    SafetyAuditEvent,
    SafetyDecision,
    SafetyFinding,
    SafetyReport,
    SafetyScanRequest,
    ScriptLanguage,
    ToolKind,
)
from tool.safety._policy import (
    ToolSafetyPolicy,
    load_safety_policy,
)
from tool.safety._guard import ToolSafetyGuard
from tool.safety._rules import SafetyRule, default_rules
from tool.safety._audit import AuditSink, InMemoryAuditSink, JsonlAuditSink
from tool.safety._tool_adapter import (
    ToolInputAdapter,
    ToolRequestError,
    build_default_adapters,
)
from tool.safety._filter import ToolScriptSafetyFilter
from tool.wrapper import SafetyCheckedExecutor, SafetyWrappedCallable

__all__ = [
    "AuditSink",
    "Evidence",
    "InMemoryAuditSink",
    "JsonlAuditSink",
    "RiskCategory",
    "RiskLevel",
    "SafetyAuditError",
    "SafetyAuditEvent",
    "SafetyCheckedExecutor",
    "SafetyDecision",
    "SafetyFinding",
    "SafetyGuardError",
    "SafetyPolicyError",
    "SafetyReport",
    "SafetyRule",
    "SafetyScanRequest",
    "SafetyScannerError",
    "SafetyWrappedCallable",
    "ScriptLanguage",
    "ToolInputAdapter",
    "ToolKind",
    "ToolRequestError",
    "ToolSafetyGuard",
    "ToolSafetyPolicy",
    "ToolScriptSafetyFilter",
    "build_default_adapters",
    "default_rules",
    "load_safety_policy",
]
