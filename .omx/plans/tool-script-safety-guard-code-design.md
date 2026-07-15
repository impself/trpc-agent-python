# Tool Script Safety Guard - Code Design

## 0. Scope amendment (plan only)

This document is an implementation plan only. Do not implement it in this task.

When implementation is later authorized, it must add files only. It must not modify any existing file under `trpc_agent_sdk/`, `tests/`, `examples/`, project configuration, or telemetry/filter/code-executor implementation. The deliverable is an independent reference package rooted at `tool/safety/`, accompanied by newly added tests, examples, and documentation. Its wrapper demonstrates the pre-execution seam without wiring into the framework core.

This section takes precedence over earlier integration descriptions: core Filter ordering, existing tool tracing, and existing CodeExecutor behavior are documented as future integration points, not files to change in this scoped implementation.

## 1. Implementation target

Build a deep safety module with one small decision interface. The scanner is pure and synchronous; execution-chain adapters own blocking, audit I/O, and telemetry. This keeps rule testing deterministic and lets Tool, Skill, MCP Tool, and CodeExecutor reuse the same decision engine.

The first release is a pre-execution guard, not a sandbox. It must fail closed on policy or scanner failures, block both `deny` and `needs_human_review` unless an external reviewer explicitly approves, and never place raw scripts, environment values, or secrets in reports, audit logs, metrics, or spans.

## 2. File layout

```text
tool/
  __init__.py
  safety/
      __init__.py                 # deliberately small public surface
      _models.py                  # request, finding, report, event, enums
      _policy.py                  # YAML loading, validation, normalization, hash
      _guard.py                   # ToolSafetyGuard aggregation and decision
      _rules.py                   # SafetyRule protocol and default rule registry
      _facts.py                   # internal normalized facts
      _python_scanner.py          # AST fact extraction
      _bash_scanner.py            # shell lexer/parser-lite fact extraction
      _cross_field_scanner.py     # args/cwd/env/tool metadata correlations
      _redaction.py               # evidence and telemetry redaction
      _audit.py                   # AuditSink, JSONL and in-memory adapters
      _telemetry.py               # span attributes and safety metrics
      _tool_adapter.py            # tool input -> SafetyScanRequest
      _filter.py                  # terminal pre-execution Tool filter
      _exceptions.py              # typed policy/scanner/audit errors
    wrapper.py                    # generic pre-execution callable wrapper
scripts/
  tool_safety_check.py
tests/
  tool_safety/
scripts/
  tool_safety_check.py
examples/tool_safety/
  tool_safety_policy.yaml
  samples/
  tool_safety_report.json
  tool_safety_audit.jsonl
  README.md
tests/
  tools/safety/
    test_policy.py
    test_guard.py
    test_python_scanner.py
    test_bash_scanner.py
    test_cross_field_scanner.py
    test_redaction.py
    test_audit.py
    test_filter.py
    test_tool_adapter.py
    test_performance.py
    test_wrapper.py
    test_cli.py
examples/
  tool_safety/
    tool_safety_policy.yaml
    samples/
    tool_safety_report.json
    tool_safety_audit.jsonl
docs/
  tool_safety_guard.md
```

Do not create one class per rule. Use three substantial rule modules (Python, Bash, cross-field) that extract reusable facts once and evaluate a rule catalog. This gives the module depth and avoids traversing the same script six times.

## 3. Public interfaces

Only export the types callers need:

```python
from trpc_agent_sdk.tools.safety import (
    AuditSink,
    JsonlAuditSink,
    SafetyAuditEvent,
    SafetyDecision,
    SafetyFinding,
    SafetyReport,
    SafetyRule,
    SafetyScanRequest,
    ToolSafetyGuard,
    ToolScriptSafetyFilter,
    load_safety_policy,
)
```

Core scanner interface:

```python
class SafetyRule(Protocol):
    def scan(
        self,
        request: SafetyScanRequest,
        policy: ToolSafetyPolicy,
    ) -> Iterable[SafetyFinding]: ...


class ToolSafetyGuard:
    def __init__(
        self,
        policy: ToolSafetyPolicy,
        *,
        rules: Sequence[SafetyRule] | None = None,
    ) -> None: ...

    def scan(self, request: SafetyScanRequest) -> SafetyReport: ...
```

`scan` performs no file writes, network access, process creation, or telemetry emission. Custom rules are appended to the defaults unless the caller explicitly constructs a replacement rule list.

Audit seam:

```python
class AuditSink(Protocol):
    async def emit(self, event: SafetyAuditEvent) -> None: ...
```

`JsonlAuditSink` serializes one event per line with an async lock and performs the short blocking append in `asyncio.to_thread`. `InMemoryAuditSink` remains test-only.

## 4. Data models and invariants

Use Pydantic models with `ConfigDict(extra="forbid")`. Policy and report models should be immutable where practical.

```python
class SafetyScanRequest(BaseModel):
    tool_name: str
    tool_kind: ToolKind
    language: ScriptLanguage
    script: str = Field(repr=False)
    argv: tuple[str, ...] = ()
    cwd: str | None = None
    env: Mapping[str, str] = Field(default_factory=dict, repr=False)
    metadata: Mapping[str, JsonValue] = Field(default_factory=dict)
    requested_timeout_seconds: float | None = None


class SafetyFinding(BaseModel):
    rule_id: str
    category: RiskCategory
    risk_level: RiskLevel
    decision: SafetyDecision
    evidence: Evidence
    recommendation: str


class SafetyReport(BaseModel):
    report_id: str
    decision: SafetyDecision
    risk_level: RiskLevel
    rule_ids: tuple[str, ...]
    findings: tuple[SafetyFinding, ...]
    recommendation: str
    policy_hash: str
    script_sha256: str
    scan_duration_ms: float
    redacted: bool
```

Invariants:

- Reports never serialize `script`, raw `argv`, `cwd`, or environment values.
- Evidence contains a bounded, redacted snippet (default 160 characters), line and column when available.
- `rule_ids` are sorted and de-duplicated for stable output.
- Aggregate decision precedence is `deny > needs_human_review > allow`.
- Aggregate risk precedence is `critical > high > medium > low > info`.
- A report with no findings is `allow/info`; a parse ambiguity or unsupported execution shape is `needs_human_review/medium`, never silent allow.
- Policy hash is SHA-256 over canonical JSON after validation and normalization.

## 5. Policy module

`load_safety_policy(path)` reads YAML with `yaml.safe_load`, validates it through Pydantic, normalizes hosts, paths, and commands, and raises a typed `SafetyPolicyError` before any tool is registered.

Suggested top-level schema:

```yaml
version: 1
defaults:
  unknown_construct: needs_human_review
  guard_error: deny
  human_review_blocks_execution: true
limits:
  max_timeout_seconds: 30
  max_output_bytes: 1048576
  max_script_bytes: 262144
  max_sleep_seconds: 10
  max_parallel_tasks: 32
network:
  allow_domains: [api.github.com, "*.internal.example.com"]
  deny_ip_literals: true
commands:
  allow: [python, python3, pytest, git]
  deny: [sudo, su, chmod, chown, mount, nc, ncat]
paths:
  deny:
    - ~/.ssh
    - /etc
    - /root
    - .env
    - "**/*credentials*"
dependencies:
  decision: needs_human_review
tools:
  workspace_exec:
    execution_capable: true
    language: bash
    fields:
      script: command
      cwd: cwd
      env: env
      timeout: timeout_sec
```

Normalization rules:

- Domains are lowercase, IDNA-normalized, and stripped of a trailing dot. Wildcards match exactly one declared suffix and never use substring matching.
- Paths use lexical normalization only. Static scanning must not touch the filesystem or claim to resolve symlinks.
- Command allowlisting applies to the parsed executable basename. Any shell operator, substitution, redirection, background marker, or secondary command is independently evaluated.
- Invalid YAML, unknown keys, invalid enum values, negative limits, or an unusable tool-field mapping fail startup.

Changing the YAML must change domains, denied paths, allowed commands, limits, and per-rule action without a code modification.

## 6. Scanner implementation

### 6.1 Common fact model

The two language scanners produce internal `ScriptFacts` containing normalized observations:

```text
file accesses, file writes, URLs/hosts, imported modules, function calls,
executables, shell operators, pipelines, redirections, background jobs,
loops, sleeps, concurrency/fork primitives, dependency installs,
secret sources, output/file/network sinks, dynamic or unresolved expressions
```

Facts carry source location and a bounded source slice. Evaluators convert facts into stable findings using a central rule catalog. Rule IDs should be stable strings such as:

```text
FILE001_RECURSIVE_DELETE
FILE002_DENIED_PATH
FILE003_CREDENTIAL_READ
NET001_NON_ALLOWLIST_HOST
NET002_DYNAMIC_DESTINATION
PROC001_SUBPROCESS
PROC002_SHELL_OPERATOR
PROC003_PRIVILEGE_ESCALATION
DEP001_ENVIRONMENT_MUTATION
RES001_UNBOUNDED_LOOP
RES002_FORK_BOMB
RES003_EXCESSIVE_SLEEP
RES004_LARGE_WRITE
SEC001_SECRET_TO_OUTPUT
SEC002_SECRET_TO_FILE
SEC003_SECRET_TO_NETWORK
ANL001_PARSE_AMBIGUITY
```

### 6.2 Python scanner

Parse with `ast.parse`; syntax errors yield `ANL001_PARSE_AMBIGUITY` and human review. Build an alias table so `import requests as r`, `from subprocess import run`, and simple assigned aliases resolve to canonical calls.

Recognize at minimum:

- `os.remove/unlink/rmdir`, `shutil.rmtree`, `Path.unlink/rmdir/write_text/write_bytes`, and `open(..., "w"/"a"/"x")`.
- Reads of `.env`, `~/.ssh`, private key files, cloud credential paths, netrc, kube config, and names containing credential/token/secret patterns.
- `requests.*`, `aiohttp`, `urllib`, `httpx`, and `socket` destinations. Literal allowlisted hosts pass; non-allowlisted literals deny; computed destinations require review.
- `subprocess.*`, `os.system`, `os.popen`, `pty.spawn`, multiprocessing/process creation, `shell=True`, and command strings containing shell grammar.
- Dependency mutation through `pip`, `python -m pip`, `npm/yarn/pnpm`, `apt/apt-get`, `apk`, `yum/dnf`, `brew`, and conda install commands.
- `while True`, obviously non-terminating loops, `os.fork`, multiprocessing explosions, very long sleeps, oversized constant writes, and excessive constant fan-out.
- Taint from `os.environ`, `getenv`, credential files, private-key literals, and secret-looking variables into `print`, logging, file writes, subprocess arguments, and network payload/query/header sinks.

Keep taint analysis deliberately local: literals, names, direct assignments, f-strings, concatenation, and shallow container construction. More dynamic flows become human review rather than a false claim of safety.

### 6.3 Bash scanner

Implement a conservative lexer rather than executing or expanding the shell. Preserve quoting state and source offsets, split command segments at `;`, newline, `&&`, `||`, `|`, `&`, redirections, command substitution, and process substitution.

Detect at minimum:

- `rm -rf/-fr`, recursive overwrite/copy into denied paths, destructive `find -delete`, and reads of denied credential paths through `cat`, `sed`, `awk`, `source`, `.`, `grep`, `head`, and `tail`.
- `curl`, `wget`, `nc/ncat`, `ssh/scp`, and URLs passed to common CLIs. Dynamic host expressions require review.
- Pipelines, command substitution, `eval`, `bash -c`, `sh -c`, background jobs, privilege escalation, and commands outside the allowlist.
- Package installation commands and shell downloads piped into an interpreter.
- `while true`, `for ((;;))`, fork-bomb token patterns, long sleeps, unbounded background loops, and large constant generators such as `dd`/`fallocate` beyond policy.
- Secret environment variables or credential-file content flowing into `echo`, `printf`, loggers, redirection targets, or network arguments.

Malformed quoting or unsupported shell grammar yields review. Never use `shell=True` to validate a script.

### 6.4 Cross-field scanner

Evaluate request fields together:

- Reject denied or escaping working directories.
- Compare requested timeout with policy maximum.
- Scan `argv` as data and reject option injection where a tool adapter marks an argument as an executable or destination.
- Inspect environment variable names and values only in memory. Values matching secrets become taint sources and are immediately registered with the redactor.
- Use `metadata` to recognize MCP server identity, Skill name, CodeExecutor type, and declared sandbox/resource limits.
- An execution-capable Tool without a valid mapping is `needs_human_review`.

## 7. Decision engine

`ToolSafetyGuard.scan` should be short and deterministic:

```python
def scan(self, request: SafetyScanRequest) -> SafetyReport:
    started = perf_counter()
    validate_request_size(request, self._policy)
    findings = [
        finding
        for rule in self._rules
        for finding in rule.scan(request, self._policy)
    ]
    findings = deduplicate_and_redact(findings, request.env.values())
    return build_report(
        request=request,
        policy=self._policy,
        findings=findings,
        elapsed_ms=(perf_counter() - started) * 1000,
    )
```

Unexpected programmer defects should propagate in direct scanner use. Execution adapters catch only typed guard exceptions, convert them to `GUARD001_INTERNAL_ERROR` with a `deny/critical` decision, and log the exception without request content. This makes the production path fail closed without hiding defects in tests.

## 8. Tool, Skill, and MCP integration

### 8.1 Terminal filter ordering

The current runner appends callback filters after normal Tool filters, so a callback can mutate a safe command into a dangerous one. Add a minimal ordering seam:

```python
class BaseFilter(FilterABC):
    @property
    def terminal_before_handler(self) -> bool:
        return False
```

`FilterRunner` composes filters as:

```python
normal_filters + extra_filters + terminal_filters
```

Apply the same composition to regular and streaming runners. Existing filters retain current order; only filters opting into the terminal phase move after callback filters. Add a regression test in which a callback changes `echo ok` to `rm -rf /` and the terminal safety filter blocks before the handler spy is called.

### 8.2 ToolScriptSafetyFilter

`ToolScriptSafetyFilter.terminal_before_handler` returns `True`. Its `_before` method:

1. Gets the current Tool identity and invocation context.
2. Uses `ToolRequestAdapter` plus policy field mappings to create `SafetyScanRequest`.
3. Scans once and builds one `SafetyAuditEvent`.
4. Stores sanitized trace arguments in invocation-local telemetry state.
5. Sets current-span safety attributes and records dedicated counters/histogram.
6. Emits the audit event before allowing execution.
7. For `deny` or `needs_human_review`, sets `rsp.is_continue = False` and returns a structured blocked response containing the report ID, decision, risk, rule IDs, evidence, and recommendation.

Built-in adapters:

| Tool | script | cwd | env | timeout |
|---|---|---|---|---|
| `workspace_exec` | `command` | `cwd` | `env` | `timeout_sec` |
| `skill_run` | `command` | `cwd` | `env` | `timeout` |
| `skill_exec` | `command` | `cwd` | `env` | `timeout` |

MCP and custom execution Tools use the same declarative YAML mapping. A Tool marked `execution_capable` but lacking a usable mapping is blocked for human review.

Registration example:

```python
policy = load_safety_policy("tool_safety_policy.yaml")
guard = ToolSafetyGuard(policy)
safety_filter = ToolScriptSafetyFilter(
    guard=guard,
    audit_sink=JsonlAuditSink("tool_safety_audit.jsonl"),
)

tool = WorkspaceExecTool(filters=[safety_filter])
```

V1 guarantees filtering for non-streaming executable Tools, which includes the named Skill execution Tools and normal MCP Tools. Document that a future streaming executor must call the same guard or gain a common guarded entry path; do not imply `BaseTool.run_async` protects a `run_streaming` override that bypasses it.

## 9. CodeExecutor wrapper

Add `SafetyCheckedCodeExecutor(BaseCodeExecutor)` as an adapter around an existing executor. A `wrap(...)` classmethod copies the delegate's behavior fields (`stateful`, delimiters, retry settings, workspace runtime, and related BaseCodeExecutor options) so consumers can replace the executor without changing agent code.

Execution flow:

```python
async def execute_code(self, execution_input: CodeExecutionInput) -> CodeExecutionResult:
    requests = build_requests_for_code_blocks(execution_input)
    report = SafetyReport.combine(self._guard.scan(item) for item in requests)
    await self._audit_sink.emit(event_from(report))
    record_safety_telemetry(report)
    if report.decision is not SafetyDecision.ALLOW:
        return CodeExecutionResult(
            outcome=Outcome.OUTCOME_FAILED,
            output=render_blocked_result(report),
        )
    result = await self._delegate.execute_code(execution_input)
    return truncate_execution_output(result, self._policy.limits.max_output_bytes)
```

The base executor interface has no universal timeout parameter. Therefore the wrapper must not pretend it can enforce runtime timeout for every delegate. The caller supplies an `effective_timeout_seconds`, or a known executor adapter extracts it. If the guard cannot establish that the effective timeout is within policy, execution needs human review. Real CPU, memory, process-count, filesystem, and network enforcement remains the workspace runtime/sandbox responsibility.

## 10. Redaction, audit, and telemetry

Redaction runs before serialization. It covers actual environment values plus recognizable bearer tokens, API keys, passwords, private-key blocks, cloud access keys, and secret assignments. Evidence is truncated after redaction. Unit tests must assert secret literals are absent from `model_dump_json()`, JSONL, logger capture, and span export.

Audit event fields:

```text
event_id, timestamp, report_id, invocation_id, tool_name, tool_kind,
decision, risk_level, rule_ids, duration_ms, redacted, blocked,
policy_hash, script_sha256, scanner_version
```

Do not emit raw script, command, arguments, environment, cwd, or unredacted evidence into JSONL.

Set these span attributes when OpenTelemetry is active; no-op safely when no span is recording:

```text
tool.safety.decision
tool.safety.risk_level
tool.safety.rule_id              # comma-separated bounded list
tool.safety.blocked
tool.safety.redacted
tool.safety.scan_duration_ms
tool.safety.policy_hash
```

Add dedicated metrics:

```text
trpc_agent.tool_safety.scan_count{decision,risk_level,tool_name}
trpc_agent.tool_safety.block_count{decision,rule_id,tool_name}
trpc_agent.tool_safety.scan_duration_ms{decision,tool_name}
```

### Trace argument leak fix

The current tool processor traces original `arguments` after execution. Add an invocation-scoped `ToolTraceState` held by `ContextVar`:

```python
token = begin_tool_trace_scope()
try:
    result = await tool.run_async(...)
    trace_tool_call(args=get_trace_arguments_or(arguments), ...)
finally:
    end_tool_trace_scope(token)
```

The safety filter writes redacted arguments into the active state. Scope setup and cleanup belong in the tool processor, covering both success and error paths and preserving isolation across concurrent tool calls. This is safer than a global cache and keeps raw secrets out of existing spans.

## 11. CLI and examples

Use `argparse` to avoid a new dependency. Make `main(argv: Sequence[str] | None = None) -> int` directly testable.

```text
python scripts/tool_safety_check.py \
  --policy examples/tool_safety/tool_safety_policy.yaml \
  --language python \
  --script-file examples/tool_safety/samples/safe_python.py \
  --tool-name demo \
  --output tool_safety_report.json \
  --audit-file tool_safety_audit.jsonl
```

Also support `--request-json` for complete inputs and `--manifest` to scan all public samples. Exit codes: `0=allow`, `2=deny`, `3=needs_human_review`, `4=invalid input/policy`.

Provide at least these 14 manifest cases:

```text
safe_python, safe_bash, dangerous_recursive_delete, credential_read,
non_allowlist_network, allowlist_network, subprocess_call, shell_injection,
dependency_install, infinite_loop, secret_output, bash_pipeline,
dynamic_url_review, dynamic_command_review
```

Each case declares expected decision and expected rule IDs. The manifest runner writes an array of reports and one audit line per scan.

## 12. Test-first coding order

Implement in small, independently verifiable slices:

1. **Models and policy**: enums, immutable models, YAML validation, normalization, canonical hash. Tests cover unknown keys, wildcard host semantics, path normalization, and policy-only behavior changes.
2. **Redaction**: bounded evidence and environment-value scrubbing. Tests serialize every output surface and assert the secret is absent.
3. **Python vertical slice**: safe script, recursive deletion, credential read, allowlisted/non-allowlisted network, subprocess, install, loop, and secret output through the public `ToolSafetyGuard.scan` interface.
4. **Bash vertical slice**: safe command, `rm -rf`, credential read, pipeline/injection, install, fork bomb, long sleep, network rules, and ambiguity review.
5. **Cross-field checks**: cwd, argv, env, timeout, unknown execution-capable Tool, and report aggregation.
6. **Audit and telemetry**: one event per attempt, required fields, concurrency isolation, span attributes, metrics, and no raw arguments.
7. **Terminal Filter integration**: callback mutation, handler spy, all three decisions, fail-closed scanner/audit errors, and Skill/MCP-style mapped inputs.
8. **CodeExecutor adapter**: fake delegate proves deny/review never calls it, allow calls exactly once, output is capped, and unknown timeout requires review.
9. **CLI and deliverables**: manifest execution, JSON schema, exit codes, example report/audit, and README.
10. **Performance and regression**: warm up once, scan a deterministic 500-line Python and Bash fixture repeatedly, assert p95 below 1 second, then run the full test suite and linters.

Primary tests should use public module interfaces. Test internal parsers only for lexer/AST edge cases that are otherwise hard to diagnose.

## 13. Acceptance mapping

| Acceptance requirement | Code/test proof |
|---|---|
| 12+ runnable samples | manifest CLI integration test and 14 fixtures |
| high-risk detection >= 90% | parameterized benchmark matrix with explicit denominator |
| safe false positives <= 10% | separate benign corpus and rate assertion |
| key read/delete/non-allowlist = 100% | mandatory category parameterization for Python and Bash |
| 500 lines < 1 second | deterministic p95 performance test |
| structured fields | Pydantic schema and JSON snapshot tests |
| policy changes behavior | load two YAML policies against identical input |
| pre-execution block + audit | terminal Filter handler-spy integration test |
| telemetry fields | in-memory OTel exporter/metric reader assertions |
| cannot replace sandbox | README threat-model and responsibility matrix |

## 14. Documentation boundary statement

The README must state the responsibility split plainly:

```text
Filter / Safety Guard: pre-execution static policy decision and redaction.
CodeExecutor adapter: applies the same decision before delegated execution.
Sandbox / workspace runtime: runtime isolation and hard resource/network/filesystem limits.
Telemetry / audit: evidence that a decision occurred; not an enforcement mechanism.
```

Known bypasses include obfuscation, dynamic code generation, runtime downloads, symlink races, encoded payloads, reflection, native extensions, interpreter bugs, shell grammar not modeled by the parser-lite scanner, indirect data flow, and behavior that depends on runtime state. These limits justify human review for ambiguity and make sandboxing mandatory even after an `allow` decision.

## 15. Definition of done

- Public interfaces and example imports are stable and documented.
- `deny` and `needs_human_review` cannot reach the real handler/delegate by default.
- Every attempt emits exactly one sanitized audit event before execution or blocking response.
- Existing Tool filters preserve behavior except for the opt-in terminal ordering seam.
- Tool tracing no longer records raw guarded arguments.
- All 14 examples match expected decisions and mandatory categories reach 100%.
- The 500-line performance test passes with margin, not just at the one-second boundary.
- Full targeted tests, formatting, lint, and type checks pass.
- Documentation explicitly says the guard reduces risk but cannot replace a sandbox.
