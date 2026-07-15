"""Standalone Tool Script Safety Guard.

Public surface is exported via :mod:`tool`. Internal modules are private.
"""

from tool.safety._exceptions import (
    SafetyAuditError,
    SafetyGuardError,
    SafetyPolicyError,
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
from tool.safety._policy import ToolSafetyPolicy, load_safety_policy
from tool.safety._guard import ToolSafetyGuard
from tool.safety._rules import SafetyRule, default_rules
from tool.safety._audit import AuditSink, InMemoryAuditSink, JsonlAuditSink
from tool.safety._tool_adapter import (
    ToolInputAdapter,
    ToolRequestError,
    build_default_adapters,
)
from tool.safety._filter import ToolScriptSafetyFilter

__all__ = [
    "AuditSink",
    "Evidence",
    "InMemoryAuditSink",
    "JsonlAuditSink",
    "RiskCategory",
    "RiskLevel",
    "SafetyAuditError",
    "SafetyAuditEvent",
    "SafetyDecision",
    "SafetyFinding",
    "SafetyGuardError",
    "SafetyPolicyError",
    "SafetyReport",
    "SafetyRule",
    "SafetyScanRequest",
    "SafetyScannerError",
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
