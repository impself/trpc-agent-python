"""Tests for the SafetyWrappedCallable and SafetyCheckedExecutor."""

from __future__ import annotations

import pytest

from tool.safety._audit import InMemoryAuditSink
from tool.safety._filter import BlockedExecutionError, ToolScriptSafetyFilter
from tool.safety._guard import ToolSafetyGuard
from tool.safety._models import ScriptLanguage, ToolKind
from tool.safety._policy import load_safety_policy_dict
from tool.wrapper import SafetyCheckedExecutor, SafetyWrappedCallable


@pytest.fixture
def guard(strict_policy_dict):
    return ToolSafetyGuard(load_safety_policy_dict(strict_policy_dict))


@pytest.fixture
def filter_(guard):
    return ToolScriptSafetyFilter(guard, audit_sink=InMemoryAuditSink())


def test_wrapped_callable_allows_safe(guard):
    calls = []

    def delegate(script: str) -> str:
        calls.append(script)
        return "ok"

    wrapped = SafetyWrappedCallable(
        guard, delegate,
        tool_name="python_exec",
        language=ScriptLanguage.PYTHON,
        script_kw="script",
    )
    assert wrapped(script="print('hi')") == "ok"
    assert calls == ["print('hi')"]


def test_wrapped_callable_blocks_danger(guard):
    def delegate(script: str) -> str:
        return "ran"

    wrapped = SafetyWrappedCallable(
        guard, delegate,
        tool_name="python_exec",
        language=ScriptLanguage.PYTHON,
        script_kw="script",
    )
    with pytest.raises(BlockedExecutionError):
        wrapped(script="import shutil\nshutil.rmtree('/x')")


def test_wrapped_callable_supports_positional(guard):
    def delegate(script: str) -> str:
        return f"got:{script}"

    wrapped = SafetyWrappedCallable(
        guard, delegate,
        tool_name="python_exec",
        language=ScriptLanguage.PYTHON,
        script_pos=0,
    )
    assert wrapped("print(1)") == "got:print(1)"


def test_executor_allow_delegates(guard):
    class FakeInput:
        code_blocks = [type("Block", (), {"code": "print('a')"})()]

    class FakeResult:
        outcome = "SUCCESS"
        output = "x" * 100

    class FakeExecutor:
        async def execute_code(self, inp):
            assert inp is fake_input
            return FakeResult()

    delegate = FakeExecutor()
    wrapped = SafetyCheckedExecutor(guard, delegate,
                                    audit_sink=InMemoryAuditSink())
    fake_input = FakeInput()
    result = asyncio.run(wrapped.execute_code(fake_input))  # noqa: F821
    assert result.outcome == "SUCCESS"


def test_executor_deny_does_not_delegate(guard):
    class FakeInput:
        code_blocks = [type("Block", (),
                            {"code": "import shutil\nshutil.rmtree('/x')"})()]

    called = []

    class FakeExecutor:
        async def execute_code(self, inp):
            called.append(True)
            return None

    wrapped = SafetyCheckedExecutor(guard, FakeExecutor(),
                                    audit_sink=InMemoryAuditSink())
    result = asyncio.run(wrapped.execute_code(FakeInput()))  # noqa: F821
    assert called == []
    assert "blocked" in result.output or "tool.safety" in result.output


def test_executor_truncates_output(guard):
    class FakeInput:
        code_blocks = [type("Block", (), {"code": "print('hi')"})()]

    class FakeResult:
        outcome = "SUCCESS"
        output = "x" * 4096

    class FakeExecutor:
        async def execute_code(self, inp):
            return FakeResult()

    wrapped = SafetyCheckedExecutor(guard, FakeExecutor(),
                                    audit_sink=InMemoryAuditSink())
    result = asyncio.run(wrapped.execute_code(FakeInput()))  # noqa: F821
    assert len(result.output) < 4096


# Need asyncio.run helper
import asyncio  # noqa: E402
