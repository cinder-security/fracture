from __future__ import annotations

import json
import re
import subprocess
import shlex
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_TASK_COMMAND_ALLOWLIST: dict[str, list[tuple[str, ...]]] = {
    "analysis": [("python", "-m", "pytest"), ("pytest",)],
    "memory": [("python", "-m", "pytest"), ("pytest",)],
    "implementation": [("python", "-m", "pytest"), ("pytest",)],
    "integration": [("python", "-m", "pytest"), ("pytest",)],
    "validation": [("python", "-m", "pytest"), ("pytest",)],
    "ux": [("python", "-m", "pytest"), ("pytest",)],
}

_APPROVAL_STRICTNESS = {"lenient", "balanced", "strict"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _slugify(value: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return text or "default-project"


def _dedupe_text(items: list[str]) -> list[str]:
    ordered: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if value and value not in ordered:
            ordered.append(value)
    return ordered


@dataclass
class OperationTask:
    id: str
    title: str
    kind: str
    status: str = "pending"
    priority: int = 50
    impact: int = 50
    risk: int = 30
    effort: int = 50
    reversibility: int = 50
    notes: list[str] = field(default_factory=list)
    file_hints: list[str] = field(default_factory=list)
    command_hint: str = ""
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    completed_at: str | None = None


@dataclass
class DecisionRecord:
    summary: str
    rationale: str
    timestamp: str = field(default_factory=_utc_now)


@dataclass
class MemoryEntry:
    kind: str
    summary: str
    detail: str = ""
    timestamp: str = field(default_factory=_utc_now)


@dataclass
class ExecutionRecord:
    task_id: str
    command: str
    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    changed_files_snapshot: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utc_now)


@dataclass
class ApprovalSuggestion:
    task_id: str
    ready: bool
    confidence: str
    rationale: list[str] = field(default_factory=list)
    suggested_command: str = ""
    stale: bool = False
    changed_files_snapshot: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utc_now)


@dataclass
class RunPolicy:
    allow_execute: bool = False
    default_command_timeout: int = 20
    auto_execute_kinds: list[str] = field(default_factory=list)
    approval_strictness: str = "balanced"
    memory_limit: int = 20
    execution_limit: int = 10
    approval_limit: int = 10
    decision_limit: int = 20
    updated_at: str = field(default_factory=_utc_now)


def _normalize_run_policy(policy: RunPolicy) -> RunPolicy:
    policy.allow_execute = bool(policy.allow_execute)
    policy.default_command_timeout = max(1, int(policy.default_command_timeout or 20))
    policy.auto_execute_kinds = [
        kind for kind in _dedupe_text([str(item or "").strip().lower() for item in policy.auto_execute_kinds])
        if kind in _TASK_COMMAND_ALLOWLIST
    ]
    if str(policy.approval_strictness or "").strip().lower() not in _APPROVAL_STRICTNESS:
        policy.approval_strictness = "balanced"
    else:
        policy.approval_strictness = str(policy.approval_strictness).strip().lower()
    policy.memory_limit = max(1, int(policy.memory_limit or 20))
    policy.execution_limit = max(1, int(policy.execution_limit or 10))
    policy.approval_limit = max(1, int(policy.approval_limit or 10))
    policy.decision_limit = max(1, int(policy.decision_limit or 20))
    return policy


def _build_policy_summary(policy: RunPolicy) -> str:
    auto = ",".join(policy.auto_execute_kinds) if policy.auto_execute_kinds else "none"
    return (
        f"execute={'on' if policy.allow_execute else 'off'}; "
        f"timeout={policy.default_command_timeout}; "
        f"auto={auto}; "
        f"approval={policy.approval_strictness}; "
        f"retain=m{policy.memory_limit}/e{policy.execution_limit}/a{policy.approval_limit}/d{policy.decision_limit}"
    )


def _build_memory_summary(state: "ProjectState") -> str:
    recent_memory = state.memory[:5]
    recent_executions = state.executions[:5]
    recent_approvals = state.approvals[:5]

    memory_kinds: dict[str, int] = {}
    for entry in recent_memory:
        memory_kinds[entry.kind] = memory_kinds.get(entry.kind, 0) + 1

    memory_blob = ",".join(
        f"{kind}:{count}" for kind, count in sorted(memory_kinds.items())
    ) or "none"

    pass_count = sum(1 for item in recent_executions if item.success)
    fail_count = sum(1 for item in recent_executions if not item.success)
    approval_ready = sum(1 for item in recent_approvals if item.ready and not item.stale)
    approval_review = sum(1 for item in recent_approvals if not item.ready or item.stale)

    return (
        f"memory={memory_blob}; "
        f"executions=pass:{pass_count},fail:{fail_count}; "
        f"approvals=ready:{approval_ready},review:{approval_review}"
    )


def _build_tactical_summary(state: "ProjectState") -> str:
    recent_memory = state.memory[:10]
    recent_executions = state.executions[:10]
    recent_approvals = state.approvals[:10]

    failure_counts: dict[str, int] = {}
    for execution in recent_executions:
        if not execution.success:
            failure_counts[execution.task_id] = failure_counts.get(execution.task_id, 0) + 1

    repeated_failures = [
        f"{task_id}:{count}"
        for task_id, count in sorted(failure_counts.items())
        if count >= 2
    ]

    stale_count = sum(1 for approval in recent_approvals if approval.stale)

    memory_kinds: dict[str, int] = {}
    for entry in recent_memory:
        memory_kinds[entry.kind] = memory_kinds.get(entry.kind, 0) + 1
    dominant_memory = "none"
    if memory_kinds:
        dominant_memory = sorted(
            memory_kinds.items(),
            key=lambda item: (-item[1], item[0]),
        )[0][0]

    return (
        f"mode={state.operating_mode or 'build'}; "
        f"repeat_failures={','.join(repeated_failures) or 'none'}; "
        f"stale_approvals={stale_count}; "
        f"dominant_memory={dominant_memory}"
    )


def _build_planner_posture(state: "ProjectState") -> str:
    mode = state.operating_mode or "build"
    if _latest_validation_is_narrow(state):
        return "stabilize: broaden verification scope before closing the active integration slice."
    if mode == "stabilize":
        return "stabilize: favor verification and integration until failures stop."
    if mode == "hotfix":
        return "hotfix: bias toward fast validation and closure on the active regression."
    if mode == "refactor":
        return "refactor: bias toward analysis, memory updates, and safer structural change."
    return "build: keep shipping the next narrow execution slice."


@dataclass
class ProjectState:
    project: str
    slug: str
    workspace: str
    objective: str
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    tasks: list[OperationTask] = field(default_factory=list)
    decisions: list[DecisionRecord] = field(default_factory=list)
    memory: list[MemoryEntry] = field(default_factory=list)
    next_action: str = ""
    current_focus: str = ""
    focus_reason: str = ""
    preferred_focus_task_id: str = ""
    operating_mode: str = "build"
    memory_summary: str = ""
    tactical_summary: str = ""
    session_count: int = 0
    last_session_summary: str = ""
    executions: list[ExecutionRecord] = field(default_factory=list)
    approvals: list[ApprovalSuggestion] = field(default_factory=list)
    run_policy: RunPolicy = field(default_factory=RunPolicy)


class ProjectMemoryStore:
    def __init__(self, workspace: Path):
        self.workspace = Path(workspace).resolve()
        self.root = self.workspace / ".fracture" / "operations"
        self.root.mkdir(parents=True, exist_ok=True)

    def load(self, project: str, objective: str) -> ProjectState:
        slug = _slugify(project)
        path = self.root / f"{slug}.json"
        if not path.exists():
            return ProjectState(
                project=project,
                slug=slug,
                workspace=str(self.workspace),
                objective=objective,
            )

        payload = json.loads(path.read_text())
        tasks = [OperationTask(**item) for item in payload.get("tasks", [])]
        decisions = [DecisionRecord(**item) for item in payload.get("decisions", [])]
        memory = [MemoryEntry(**item) for item in payload.get("memory", [])]
        executions = [ExecutionRecord(**item) for item in payload.get("executions", [])]
        approvals = [ApprovalSuggestion(**item) for item in payload.get("approvals", [])]
        run_policy = _normalize_run_policy(RunPolicy(**payload.get("run_policy", {})))
        return ProjectState(
            project=str(payload.get("project") or project),
            slug=str(payload.get("slug") or slug),
            workspace=str(payload.get("workspace") or self.workspace),
            objective=str(payload.get("objective") or objective),
            created_at=str(payload.get("created_at") or _utc_now()),
            updated_at=str(payload.get("updated_at") or _utc_now()),
            tasks=tasks,
            decisions=decisions,
            memory=memory,
            next_action=str(payload.get("next_action") or ""),
            current_focus=str(payload.get("current_focus") or ""),
            focus_reason=str(payload.get("focus_reason") or ""),
            preferred_focus_task_id=str(payload.get("preferred_focus_task_id") or ""),
            operating_mode=str(payload.get("operating_mode") or "build"),
            memory_summary=str(payload.get("memory_summary") or ""),
            tactical_summary=str(payload.get("tactical_summary") or ""),
            session_count=int(payload.get("session_count", 0) or 0),
            last_session_summary=str(payload.get("last_session_summary") or ""),
            executions=executions,
            approvals=approvals,
            run_policy=run_policy,
        )

    def save(self, state: ProjectState) -> Path:
        state.updated_at = _utc_now()
        path = self.root / f"{state.slug}.json"
        payload = asdict(state)
        path.write_text(json.dumps(payload, indent=2))
        return path


class WorkspaceContext:
    def __init__(self, workspace: Path):
        self.workspace = Path(workspace).resolve()

    def snapshot(self) -> dict[str, Any]:
        top_files: list[str] = []
        top_dirs: list[str] = []
        for child in sorted(self.workspace.iterdir(), key=lambda item: item.name.lower()):
            if child.name.startswith(".") and child.name not in {".gitignore"}:
                continue
            if child.is_dir():
                top_dirs.append(child.name)
            elif child.is_file():
                top_files.append(child.name)

        readme_title = ""
        readme_path = self.workspace / "README.md"
        if readme_path.exists():
            for line in readme_path.read_text().splitlines():
                line = line.strip()
                if line.startswith("#"):
                    readme_title = line.lstrip("#").strip()
                    break

        git_branch = ""
        git_dirty = False
        changed_files: list[str] = []
        if (self.workspace / ".git").exists():
            branch = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=self.workspace,
                capture_output=True,
                text=True,
                check=False,
            )
            git_branch = branch.stdout.strip()
            dirty = subprocess.run(
                ["git", "status", "--short"],
                cwd=self.workspace,
                capture_output=True,
                text=True,
                check=False,
            )
            changed_files = [
                line.strip().split(maxsplit=1)[-1]
                for line in dirty.stdout.splitlines()
                if line.strip()
            ][:8]
            git_dirty = bool(changed_files)

        return {
            "workspace": str(self.workspace),
            "project_name": self.workspace.name,
            "top_files": top_files[:8],
            "top_dirs": top_dirs[:8],
            "has_tests": any(name == "tests" for name in top_dirs),
            "has_readme": any(name.lower() == "readme.md" for name in top_files),
            "has_pyproject": "pyproject.toml" in top_files,
            "readme_title": readme_title,
            "primary_language": self._detect_primary_language(top_files, top_dirs),
            "git_branch": git_branch,
            "git_dirty": git_dirty,
            "changed_files": changed_files,
            "available_test_files": self._collect_test_files(),
        }

    def _detect_primary_language(self, top_files: list[str], top_dirs: list[str]) -> str:
        if "pyproject.toml" in top_files or any(name.endswith(".py") for name in top_files) or "tests" in top_dirs:
            return "python"
        if "package.json" in top_files:
            return "node"
        if "Cargo.toml" in top_files:
            return "rust"
        return "unknown"

    def _collect_test_files(self) -> list[str]:
        tests_dir = self.workspace / "tests"
        if not tests_dir.exists() or not tests_dir.is_dir():
            return []
        return sorted(
            str(path.relative_to(self.workspace))
            for path in tests_dir.glob("test_*.py")
            if path.is_file()
        )[:20]


class Planner:
    def build_plan(self, state: ProjectState, context: dict[str, Any]) -> ProjectState:
        seed_tasks = self._seed_tasks(state.objective, context)
        existing_titles = {task.title: task for task in state.tasks}

        for task in seed_tasks:
            if task.title in existing_titles:
                continue
            state.tasks.append(task)

        for task in state.tasks:
            task.command_hint = self._derive_command_hint(
                state=state,
                kind=task.kind,
                file_hints=task.file_hints,
                context=context,
                fallback=task.command_hint,
            )
            task.notes = self._refresh_command_notes(state, task, task.notes, task.command_hint)
        state.operating_mode = self._derive_operating_mode(state)
        self._recompute_priorities(state, context)

        state.tasks.sort(
            key=lambda item: (
                0 if item.status == "in_progress" else 1 if item.status == "pending" else 2,
                -item.priority,
                item.effort,
            )
        )
        state.preferred_focus_task_id = self._preferred_focus_task_id(state)
        state.focus_reason = self._build_focus_reason(state)
        return state

    def _seed_tasks(self, objective: str, context: dict[str, Any]) -> list[OperationTask]:
        normalized = str(objective or "").strip()
        objective_hint = normalized.lower()
        tests_task = (
            "Extend the existing test suite for plan persistence and task progression"
            if context.get("has_tests")
            else "Add smoke tests for plan persistence and task progression"
        )
        blueprint = [
            (
                "Map current architecture and identify the narrowest insertion point",
                "analysis",
                95,
                90,
                20,
                25,
                90,
                self._task_notes(kind="analysis", objective=normalized, context=context),
                ["fracture/cli.py", "fracture/core", "tests"],
                "python -m pytest tests/test_cli_smoke.py -q",
            ),
            (
                "Define the project memory schema and session recap format",
                "memory",
                92,
                88,
                15,
                30,
                95,
                self._task_notes(kind="memory", objective=normalized, context=context),
                ["fracture/core/operations.py"],
                "python -m pytest tests/test_cli_smoke.py -k operate -q",
            ),
            (
                "Implement the planner/executor/critic core loop",
                "implementation",
                98,
                95,
                35,
                70,
                70,
                self._task_notes(kind="implementation", objective=normalized, context=context),
                ["fracture/core/operations.py", "fracture/cli.py"],
                "python -m pytest tests/test_cli_smoke.py -k operate -q",
            ),
            (
                "Expose the operating loop through a CLI command",
                "integration",
                94,
                86,
                20,
                45,
                85,
                self._task_notes(kind="integration", objective=normalized, context=context),
                ["fracture/cli.py", "README.md"],
                "python -m pytest tests/test_cli_smoke.py -q",
            ),
            (
                tests_task,
                "validation",
                90,
                84,
                10,
                35,
                95,
                self._task_notes(kind="validation", objective=normalized, context=context),
                ["tests/test_cli_smoke.py"],
                "python -m pytest tests/test_cli_smoke.py -k operate -q",
            ),
        ]

        if "ui" in objective_hint or "interface" in objective_hint:
            blueprint.append(
                (
                    "Design a lightweight operator view for current focus and next action",
                    "ux",
                    82,
                    70,
                    15,
                    45,
                    80,
                    self._task_notes(kind="ux", objective=normalized, context=context),
                    ["fracture/ui/control_center.py", "fracture/cli.py"],
                    "python -m pytest tests/test_cli_smoke.py -k ui -q",
                )
            )

        tasks: list[OperationTask] = []
        for index, item in enumerate(blueprint, start=1):
            title, kind, priority, impact, risk, effort, reversibility, notes, file_hints, command_hint = item
            tasks.append(
                OperationTask(
                    id=f"T{index:02d}",
                    title=title,
                    kind=kind,
                    priority=priority,
                    impact=impact,
                    risk=risk,
                    effort=effort,
                    reversibility=reversibility,
                    notes=notes,
                    file_hints=file_hints,
                    command_hint=command_hint,
                )
            )
        return tasks

    def _task_notes(self, *, kind: str, objective: str, context: dict[str, Any]) -> list[str]:
        notes = []
        if objective:
            notes.append(f"Objective: {objective}")
        if context.get("readme_title"):
            notes.append(f"Project: {context['readme_title']}")
        if context.get("primary_language") != "unknown":
            notes.append(f"Stack: {context['primary_language']}")
        if context.get("git_branch"):
            notes.append(f"Branch: {context['git_branch']}")
        if context.get("git_dirty"):
            notes.append(
                "Uncommitted changes present: "
                + ", ".join(context.get("changed_files", [])[:3])
            )
        if kind == "validation" and context.get("has_tests"):
            notes.append("Use the existing tests/ tree rather than adding a separate harness.")
        return notes

    def _derive_command_hint(
        self,
        *,
        state: ProjectState,
        kind: str,
        file_hints: list[str],
        context: dict[str, Any],
        fallback: str,
    ) -> str:
        test_files = set(context.get("available_test_files", []) or [])
        hints = [str(item or "") for item in file_hints]
        changed_files = [str(item or "") for item in context.get("changed_files", [])]

        if kind == "ux":
            if "tests/test_cli_smoke.py" in test_files:
                return "python -m pytest tests/test_cli_smoke.py -k ui -q"
            return fallback

        if kind == "validation":
            command = self._build_broader_validation_command(
                state=state,
                prioritized_paths=hints,
                changed_paths=changed_files,
                test_files=test_files,
            )
            if command:
                return command

        command = self._build_incremental_test_command(
            prioritized_paths=hints,
            changed_paths=changed_files,
            test_files=test_files,
        )
        if command:
            return command

        if "tests/test_cli_smoke.py" in hints and "tests/test_cli_smoke.py" in test_files:
            if kind == "validation":
                return "python -m pytest tests/test_cli_smoke.py -k operate -q"
            return "python -m pytest tests/test_cli_smoke.py -q"

        if any(path in hints for path in ["fracture/core/operations.py", "fracture/cli.py"]):
            if "tests/test_cli_smoke.py" in test_files:
                return "python -m pytest tests/test_cli_smoke.py -k operate -q"

        command = self._match_paths_to_tests(hints, test_files)
        if command:
            return command

        if kind in {"analysis", "memory", "implementation", "integration", "validation"} and test_files:
            prioritized = [
                "tests/test_cli_smoke.py",
                "tests/test_target_contract.py",
                "tests/test_surface_discovery.py",
            ]
            for test_file in prioritized:
                if test_file in test_files:
                    return f"python -m pytest {test_file} -q"

        return fallback

    def _match_paths_to_tests(self, hints: list[str], test_files: set[str]) -> str:
        matched_tests = self._collect_tests_from_paths(hints, test_files)
        if not matched_tests:
            return ""
        return f"python -m pytest {' '.join(matched_tests[:3])} -q"

    def _build_incremental_test_command(
        self,
        *,
        prioritized_paths: list[str],
        changed_paths: list[str],
        test_files: set[str],
    ) -> str:
        matched_tests: list[str] = []
        for test_file in self._collect_tests_from_paths(prioritized_paths, test_files):
            if test_file not in matched_tests:
                matched_tests.append(test_file)
        for test_file in self._collect_tests_from_paths(changed_paths, test_files):
            if test_file not in matched_tests:
                matched_tests.append(test_file)
            if len(matched_tests) >= 3:
                break
        if not matched_tests:
            return ""
        return f"python -m pytest {' '.join(matched_tests[:3])} -q"

    def _build_broader_validation_command(
        self,
        *,
        state: ProjectState,
        prioritized_paths: list[str],
        changed_paths: list[str],
        test_files: set[str],
    ) -> str:
        integration_targets = _latest_integration_test_targets(state)
        if len(integration_targets) > 1:
            return ""

        matched_tests: list[str] = []
        for test_file in integration_targets:
            if test_file in test_files and test_file not in matched_tests:
                matched_tests.append(test_file)
        for test_file in self._collect_tests_from_paths(prioritized_paths, test_files):
            if test_file not in matched_tests:
                matched_tests.append(test_file)
        for test_file in self._collect_tests_from_paths(changed_paths, test_files):
            if test_file not in matched_tests:
                matched_tests.append(test_file)
            if len(matched_tests) >= 3:
                break
        for test_file in [
            "tests/test_cli_smoke.py",
            "tests/test_target_contract.py",
            "tests/test_surface_discovery.py",
            "tests/test_reporting_exports.py",
            "tests/test_demo_target.py",
        ]:
            if test_file in test_files and test_file not in matched_tests:
                matched_tests.append(test_file)
            if len(matched_tests) >= 3:
                break
        if len(matched_tests) <= len(integration_targets):
            return ""
        return f"python -m pytest {' '.join(matched_tests[:3])} -q"

    def _collect_tests_from_paths(self, hints: list[str], test_files: set[str]) -> list[str]:
        stem_to_test = {
            "target": "tests/test_target_contract.py",
            "surface_discovery": "tests/test_surface_discovery.py",
            "report": "tests/test_reporting_exports.py",
            "reporting": "tests/test_reporting_exports.py",
            "demo": "tests/test_demo_target.py",
        }
        matched_tests: list[str] = []
        for hint in hints:
            normalized_hint = str(hint or "")
            if normalized_hint in test_files:
                if normalized_hint not in matched_tests:
                    matched_tests.append(normalized_hint)
                if len(matched_tests) >= 3:
                    break
                continue
            stem = Path(hint).stem.replace("test_", "")
            for key, test_file in stem_to_test.items():
                if key in stem and test_file in test_files:
                    if test_file not in matched_tests:
                        matched_tests.append(test_file)
                    break
            if len(matched_tests) >= 3:
                break
        return matched_tests[:3]

    def _refresh_command_notes(
        self,
        state: ProjectState,
        task: OperationTask,
        notes: list[str],
        command_hint: str,
    ) -> list[str]:
        preserved = [
            note for note in notes
            if not note.startswith("Validation plan:")
        ]
        command = str(command_hint or "").strip()
        if command.startswith("python -m pytest ") or command.startswith("pytest "):
            test_targets = _extract_pytest_targets(command)
            prior_integration_targets = _latest_integration_test_targets(state)
            broader_than_integration = (
                task.kind == "validation"
                and len(prior_integration_targets) == 1
                and len(test_targets) > len(prior_integration_targets)
            )
            if broader_than_integration:
                preserved.append(
                    "Validation plan: broadened from the previous integration run because the last verification scope was too narrow."
                )
            elif len(test_targets) > 1:
                preserved.append(
                    f"Validation plan: incremental test batch selected ({len(test_targets)} targets)."
                )
            elif len(test_targets) == 1:
                preserved.append(
                    "Validation plan: targeted test selection derived from current focus and diff."
                )
        return _dedupe_text(preserved)

    def _recompute_priorities(self, state: ProjectState, context: dict[str, Any]) -> None:
        changed_files = [str(item or "") for item in context.get("changed_files", [])]
        failed_task_ids = {
            execution.task_id
            for execution in state.executions[:5]
            if not execution.success
        }
        repeat_failure_counts = self._repeat_failure_counts(state.executions[:10])
        stale_approval_task_ids = {
            approval.task_id
            for approval in state.approvals[:10]
            if approval.stale
        }
        stabilize_mode = state.operating_mode == "stabilize"
        narrow_integration_validation = _latest_validation_is_narrow(state)

        for task in state.tasks:
            base_priority = self._base_priority_for_kind(task.kind, state.operating_mode)
            changed_bonus = self._changed_file_bonus(task.file_hints, changed_files)
            failure_bonus = 40 if task.id in failed_task_ids else 0
            repeat_failure_bonus = 25 if repeat_failure_counts.get(task.id, 0) >= 2 else 0
            stale_approval_bonus = 15 if task.id in stale_approval_task_ids else 0
            stabilize_bonus = 0
            narrow_validation_bonus = 0
            if stabilize_mode and task.kind in {"validation", "integration"}:
                stabilize_bonus = 20
            if narrow_integration_validation and task.kind == "validation":
                narrow_validation_bonus = 18
            task.priority = min(
                999,
                base_priority + changed_bonus + failure_bonus + repeat_failure_bonus + stale_approval_bonus + stabilize_bonus + narrow_validation_bonus,
            )
            task.notes = self._refresh_priority_notes(
                task.notes,
                changed_bonus=changed_bonus,
                failure_bonus=failure_bonus,
                repeat_failure_bonus=repeat_failure_bonus,
                stale_approval_bonus=stale_approval_bonus,
                stabilize_bonus=stabilize_bonus,
                narrow_validation_bonus=narrow_validation_bonus,
            )

    def _base_priority_for_kind(self, kind: str, mode: str = "build") -> int:
        build_defaults = {
            "analysis": 95,
            "memory": 92,
            "implementation": 98,
            "integration": 94,
            "validation": 90,
            "ux": 82,
        }
        mode_overrides = {
            "hotfix": {
                "analysis": 88,
                "memory": 84,
                "implementation": 102,
                "integration": 100,
                "validation": 106,
                "ux": 70,
            },
            "refactor": {
                "analysis": 102,
                "memory": 100,
                "implementation": 101,
                "integration": 90,
                "validation": 86,
                "ux": 78,
            },
            "stabilize": {
                "analysis": 90,
                "memory": 88,
                "implementation": 94,
                "integration": 100,
                "validation": 104,
                "ux": 76,
            },
        }
        defaults = mode_overrides.get(mode, build_defaults)
        return defaults.get(kind, build_defaults.get(kind, 50))

    def _changed_file_bonus(self, file_hints: list[str], changed_files: list[str]) -> int:
        if not changed_files:
            return 0
        bonus = 0
        for hint in file_hints:
            normalized_hint = str(hint or "")
            for changed in changed_files:
                normalized_changed = str(changed or "")
                if not normalized_hint or not normalized_changed:
                    continue
                if normalized_hint == normalized_changed:
                    bonus += 30
                elif normalized_hint.endswith("/") and normalized_changed.startswith(normalized_hint):
                    bonus += 20
                elif normalized_hint in normalized_changed or Path(normalized_hint).stem in normalized_changed:
                    bonus += 15
        return min(bonus, 60)

    def _refresh_priority_notes(
        self,
        notes: list[str],
        *,
        changed_bonus: int,
        failure_bonus: int,
        repeat_failure_bonus: int,
        stale_approval_bonus: int,
        stabilize_bonus: int,
        narrow_validation_bonus: int,
    ) -> list[str]:
        preserved = [
            note for note in notes
            if not note.startswith("Priority boost:")
        ]
        if changed_bonus:
            preserved.append(f"Priority boost: local changes overlap this task (+{changed_bonus}).")
        if failure_bonus:
            preserved.append(f"Priority boost: recent execution failure needs follow-up (+{failure_bonus}).")
        if repeat_failure_bonus:
            preserved.append(f"Priority boost: repeated failures suggest stabilization work (+{repeat_failure_bonus}).")
        if stale_approval_bonus:
            preserved.append(f"Priority boost: stale approvals need refresh before closure (+{stale_approval_bonus}).")
        if stabilize_bonus:
            preserved.append(f"Priority boost: project is in stabilize mode, favoring verification work (+{stabilize_bonus}).")
        if narrow_validation_bonus:
            preserved.append(
                f"Priority boost: recent integration validation was too narrow, so broader validation is favored (+{narrow_validation_bonus})."
            )
        return _dedupe_text(preserved)

    def _repeat_failure_counts(self, executions: list[ExecutionRecord]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for execution in executions:
            if not execution.success:
                counts[execution.task_id] = counts.get(execution.task_id, 0) + 1
        return counts

    def _should_stabilize(
        self,
        state: ProjectState,
        repeat_failure_counts: dict[str, int],
        stale_approval_task_ids: set[str],
    ) -> bool:
        repeated_failures = sum(1 for count in repeat_failure_counts.values() if count >= 2)
        stale_count = len(stale_approval_task_ids)
        recent_failures = sum(1 for execution in state.executions[:5] if not execution.success)
        return repeated_failures > 0 or stale_count > 0 or recent_failures >= 3

    def _derive_operating_mode(self, state: ProjectState) -> str:
        repeat_failure_counts = self._repeat_failure_counts(state.executions[:10])
        stale_approval_task_ids = {
            approval.task_id
            for approval in state.approvals[:10]
            if approval.stale
        }
        if self._should_stabilize(state, repeat_failure_counts, stale_approval_task_ids):
            return "stabilize"
        objective_hint = str(state.objective or "").strip().lower()
        if any(token in objective_hint for token in ["hotfix", "bug", "fix", "regression", "incident"]):
            return "hotfix"
        if any(token in objective_hint for token in ["refactor", "cleanup", "simplify", "debt"]):
            return "refactor"
        return "build"

    def _build_focus_reason(self, state: ProjectState) -> str:
        candidate = self._preferred_focus_task(state)
        if candidate is None:
            return ""

        reasons = []
        note_blob = " ".join(candidate.notes).lower()
        if _latest_validation_is_narrow(state):
            if candidate.kind == "validation":
                reasons.append("the latest integration verification was too narrow, so the next move should broaden test coverage")
            elif candidate.kind == "integration":
                reasons.append("the latest integration verification was too narrow, so this task should not close yet")
        if "recent execution failure" in note_blob:
            reasons.append("recent execution failure pushed this task to the top")
        if "repeated failures suggest stabilization work" in note_blob:
            reasons.append("repeated failures suggest this task needs stabilization")
        if "stale approvals need refresh" in note_blob:
            reasons.append("stale approvals indicate this task needs a fresh verification pass")
        if "project is in stabilize mode" in note_blob:
            reasons.append("the project is in stabilize mode, so verification work is favored")
        if "local changes overlap" in note_blob:
            reasons.append("local changes overlap this task's files")
        if not reasons:
            reasons.append(f"base priority for {candidate.kind} work is currently highest")

        return f"{candidate.id}: " + "; ".join(reasons)

    def _preferred_focus_task(self, state: ProjectState) -> OperationTask | None:
        preferred_id = str(state.preferred_focus_task_id or "").strip()
        if preferred_id:
            task = next((item for item in state.tasks if item.id == preferred_id), None)
            if task is not None:
                return task
        return next(
            (task for task in state.tasks if task.status in {"in_progress", "pending"}),
            None,
        )

    def _preferred_focus_task_id(self, state: ProjectState) -> str:
        if _latest_validation_is_narrow(state):
            validation_task = next((task for task in state.tasks if task.kind == "validation"), None)
            if validation_task is not None:
                return validation_task.id
        candidate = next(
            (task for task in state.tasks if task.status in {"in_progress", "pending"}),
            None,
        )
        return candidate.id if candidate is not None else ""


class Executor:
    def apply(
        self,
        state: ProjectState,
        *,
        done: str | None = None,
        note: str | None = None,
        execute_recommended: bool = False,
        command_timeout: int = 20,
        changed_files: list[str] | None = None,
    ) -> ProjectState:
        state.session_count += 1
        changed_files = [str(item or "") for item in (changed_files or [])]

        if note:
            state.memory.insert(
                0,
                MemoryEntry(
                    kind="note",
                    summary=note,
                    detail="Operator note captured during operating loop.",
                ),
            )

        if done:
            task = self._find_task(state.tasks, done)
            if task is not None:
                task.status = "done"
                task.updated_at = _utc_now()
                task.completed_at = task.updated_at
                state.decisions.insert(
                    0,
                    DecisionRecord(
                        summary=f"Completed {task.id}",
                        rationale=task.title,
                    ),
                )
                state.memory.insert(
                    0,
                    MemoryEntry(
                        kind="task_completion",
                        summary=f"{task.id} completed",
                        detail=task.title,
                    ),
                )

        active = next((task for task in state.tasks if task.status == "in_progress"), None)
        if active is None:
            active = next((task for task in state.tasks if task.status == "pending"), None)
            if active is not None:
                active.status = "in_progress"
                active.updated_at = _utc_now()
                state.decisions.insert(
                    0,
                    DecisionRecord(
                        summary=f"Started {active.id}",
                        rationale=active.title,
                    ),
                )

        preferred_focus = next(
            (task for task in state.tasks if task.id == state.preferred_focus_task_id),
            None,
        )
        focus_task = preferred_focus if preferred_focus is not None else active
        state.current_focus = focus_task.title if focus_task is not None else ""
        if execute_recommended and active is not None and active.command_hint:
            execution = self._run_task_command(
                active,
                Path(state.workspace),
                timeout=command_timeout,
                changed_files=changed_files,
            )
            state.executions.insert(0, execution)
            state.memory.insert(
                0,
                MemoryEntry(
                    kind="command_execution",
                    summary=f"{active.id} command {'passed' if execution.success else 'failed'}",
                    detail=f"{execution.command} (exit={execution.exit_code})",
                ),
            )
            state.decisions.insert(
                0,
                DecisionRecord(
                    summary=f"Executed {active.id}",
                    rationale=f"{execution.command} -> exit {execution.exit_code}",
                ),
            )
            active.notes = _dedupe_text(
                [
                    f"Last run: exit={execution.exit_code}",
                    *active.notes,
                ]
            )
            active.updated_at = _utc_now()
        if active is not None:
            state.last_session_summary = self._build_session_summary(state, active)
        return state

    def _find_task(self, tasks: list[OperationTask], selector: str) -> OperationTask | None:
        needle = str(selector or "").strip().lower()
        for task in tasks:
            if task.id.lower() == needle:
                return task
        for task in tasks:
            if task.title.lower() == needle:
                return task
        return None

    def _build_session_summary(self, state: ProjectState, active: OperationTask) -> str:
        completed = [task.id for task in state.tasks if task.status == "done"][:3]
        completed_blob = ", ".join(completed) if completed else "none yet"
        command = active.command_hint or "no command hint"
        focus_reason = state.focus_reason or f"{active.id}: base priority for {active.kind} work is currently highest"
        execution_blob = "not run this session"
        if state.executions:
            latest = state.executions[0]
            execution_blob = (
                f"{latest.task_id} {'pass' if latest.success else 'fail'} exit={latest.exit_code}"
            )

        approval_blob = "no approval yet"
        if state.approvals:
            latest_approval = state.approvals[0]
            approval_blob = (
                f"{latest_approval.task_id} "
                f"{'ready' if latest_approval.ready else 'review'} "
                f"{latest_approval.confidence}"
            )

        return (
            f"focus={active.id}/{active.kind}; "
            f"why={focus_reason}; "
            f"completed={completed_blob}; "
            f"command={command}; "
            f"execution={execution_blob}; "
            f"approval={approval_blob}"
        )

    def _run_task_command(
        self,
        task: OperationTask,
        workspace: Path,
        *,
        timeout: int,
        changed_files: list[str],
    ) -> ExecutionRecord:
        return run_safe_command(
            task.id,
            task.kind,
            task.command_hint,
            workspace,
            timeout=timeout,
            changed_files=changed_files,
        )


def run_safe_command(
    task_id: str,
    task_kind: str,
    command: str,
    workspace: Path,
    *,
    timeout: int,
    changed_files: list[str] | None = None,
) -> ExecutionRecord:
    changed_files = [str(item or "") for item in (changed_files or [])]
    args = shlex.split(command)
    if not args:
        return ExecutionRecord(
            task_id=task_id,
            command=command,
            success=False,
            exit_code=126,
            stderr="Blocked command: empty command string.",
            changed_files_snapshot=changed_files,
        )

    if not _command_allowed(task_kind, args):
        return ExecutionRecord(
            task_id=task_id,
            command=command,
            success=False,
            exit_code=126,
            stderr=(
                "Blocked command: prefix not allowlisted for task kind "
                f"'{task_kind}'."
            ),
            changed_files_snapshot=changed_files,
        )

    completed = subprocess.run(
        args,
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return ExecutionRecord(
        task_id=task_id,
        command=command,
        success=completed.returncode == 0,
        exit_code=int(completed.returncode),
        stdout=_trim_command_output(completed.stdout),
        stderr=_trim_command_output(completed.stderr),
        changed_files_snapshot=changed_files,
    )


def _command_allowed(task_kind: str, args: list[str]) -> bool:
    allowed_prefixes = _TASK_COMMAND_ALLOWLIST.get(task_kind, [])
    for prefix in allowed_prefixes:
        if len(args) >= len(prefix) and tuple(args[:len(prefix)]) == prefix:
            return True
    return False


def _trim_command_output(text: str, limit: int = 600) -> str:
    normalized = str(text or "").strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[:limit].rstrip() + "...<truncated>"


def _pytest_target_count(command: str) -> int:
    args = shlex.split(str(command or ""))
    return sum(1 for arg in args if str(arg).startswith("tests/"))


def _extract_pytest_targets(command: str) -> list[str]:
    args = shlex.split(str(command or ""))
    return [str(arg) for arg in args if str(arg).startswith("tests/")]


def _latest_integration_test_targets(state: "ProjectState") -> list[str]:
    integration_ids = {
        task.id
        for task in state.tasks
        if task.kind == "integration"
    }
    latest = next((item for item in state.executions if item.task_id in integration_ids), None)
    if latest is None or not latest.success:
        return []
    return _extract_pytest_targets(latest.command)[:3]


def _latest_validation_is_narrow(state: "ProjectState", task: OperationTask | None = None) -> bool:
    candidate = task
    if candidate is None:
        candidate = next((item for item in state.tasks if item.status == "in_progress"), None)
    if candidate is None or candidate.kind != "integration":
        return False
    latest = next((item for item in state.executions if item.task_id == candidate.id), None)
    if latest is None or not latest.success:
        return False
    return _pytest_target_count(latest.command) <= 1


class Critic:
    def review(
        self,
        state: ProjectState,
        *,
        changed_files: list[str] | None = None,
        strictness: str = "balanced",
    ) -> dict[str, Any]:
        changed_files = [str(item or "") for item in (changed_files or [])]
        pending = [task for task in state.tasks if task.status == "pending"]
        done = [task for task in state.tasks if task.status == "done"]
        in_progress = [task for task in state.tasks if task.status == "in_progress"]

        findings: list[str] = []
        if len(in_progress) > 1:
            findings.append("More than one task is in progress; narrow focus to one active thread.")
        if not done:
            findings.append("No completed tasks yet; prioritize getting the loop to its first finished milestone.")
        if len(pending) > 5:
            findings.append("Plan is still broad; keep the next execution slice tight.")
        if not findings:
            findings.append("Loop looks healthy; continue on the active task and keep storing decisions.")

        next_action = ""
        active_command = ""
        active_files: list[str] = []
        active = next((task for task in state.tasks if task.status == "in_progress"), None)
        validation_task = next((task for task in state.tasks if task.kind == "validation"), None)
        if active is not None:
            next_action = f"{active.id}: {active.title}"
            active_command = active.command_hint
            active_files = active.file_hints
        elif pending:
            next_action = f"{pending[0].id}: {pending[0].title}"
            active_command = pending[0].command_hint
            active_files = pending[0].file_hints

        if _latest_validation_is_narrow(state) and validation_task is not None:
            next_action = f"{validation_task.id}: Broaden validation before approval"
            active_command = validation_task.command_hint
            active_files = validation_task.file_hints

        approval = self._build_approval_suggestion(
            state,
            active,
            changed_files=changed_files,
            strictness=strictness,
        )

        return {
            "findings": findings,
            "next_action": next_action,
            "focus_reason": state.focus_reason,
            "preferred_focus_task_id": state.preferred_focus_task_id,
            "operating_mode": state.operating_mode,
            "task_counts": {
                "pending": len(pending),
                "in_progress": len(in_progress),
                "done": len(done),
            },
            "memory_highlights": [entry.summary for entry in state.memory[:3]],
            "recommended_command": active_command,
            "focus_files": active_files,
            "session_summary": state.last_session_summary,
            "last_execution": asdict(state.executions[0]) if state.executions else None,
            "approval": asdict(approval) if approval is not None else None,
        }

    def _build_approval_suggestion(
        self,
        state: ProjectState,
        active: OperationTask | None,
        *,
        changed_files: list[str],
        strictness: str,
    ) -> ApprovalSuggestion | None:
        if active is None or not state.executions:
            return None

        latest = next((item for item in state.executions if item.task_id == active.id), None)
        if latest is None:
            return None

        rationale: list[str] = []
        confidence = "low"
        ready = False
        stdout_lower = latest.stdout.lower()
        stderr_lower = latest.stderr.lower()

        if latest.success:
            rationale.append("The latest recommended command exited successfully.")
            confidence = "medium"
        else:
            rationale.append("The latest recommended command failed, so the task should stay open.")

        if latest.success and ("passed" in stdout_lower or "ok" in stdout_lower or "success" in stdout_lower):
            rationale.append("Command output includes a success marker.")
            confidence = "high"

        if stderr_lower:
            rationale.append("stderr is not empty; review it before closing the task.")
            if confidence == "high":
                confidence = "medium"

        if latest.success and not stderr_lower:
            ready = True

        if latest.success and active.kind == "validation":
            rationale.append("Validation tasks can usually be approved after a clean verification run.")
            ready = True

        if latest.success and active.kind in {"analysis", "memory", "implementation", "integration"}:
            rationale.append("This looks execution-complete, but still needs operator confirmation before marking done.")

        target_count = _pytest_target_count(latest.command)
        narrow_validation = (
            latest.success
            and active.kind == "integration"
            and target_count <= 1
        )
        if narrow_validation:
            ready = False
            confidence = "low"
            rationale.append(
                "Validation scope is narrow for this task kind; run a broader verification pass before approval."
            )

        stale = False
        snapshot = list(latest.changed_files_snapshot or [])
        if changed_files != snapshot:
            stale = True
            ready = False
            rationale.append("Local changes have shifted since the last execution; re-run before approving.")
            confidence = "low"

        if not stale:
            if strictness == "strict":
                ready = latest.success and not stderr_lower and active.kind == "validation"
                rationale.append("Strict approval policy requires a clean validation-style run.")
                confidence = "high" if ready else "low"
            elif strictness == "lenient" and latest.success and not stderr_lower:
                ready = True
                if confidence == "low":
                    confidence = "medium"

        suggested_command = f"fracture operate --workspace {state.workspace} --objective {shlex.quote(state.objective)} --done {active.id}"
        suggestion = ApprovalSuggestion(
            task_id=active.id,
            ready=ready,
            confidence=confidence,
            rationale=_dedupe_text(rationale),
            suggested_command=suggested_command,
            stale=stale,
            changed_files_snapshot=changed_files,
        )
        if not self._matches_latest_approval(state, suggestion):
            state.approvals.insert(0, suggestion)
            state.approvals = state.approvals[:10]
        else:
            suggestion = state.approvals[0]
        return suggestion

    def _matches_latest_approval(
        self,
        state: ProjectState,
        suggestion: ApprovalSuggestion,
    ) -> bool:
        if not state.approvals:
            return False
        current = state.approvals[0]
        return (
            current.task_id == suggestion.task_id
            and current.ready == suggestion.ready
            and current.confidence == suggestion.confidence
            and current.rationale == suggestion.rationale
            and current.suggested_command == suggestion.suggested_command
        )


def run_operating_loop(
    *,
    objective: str,
    workspace: str | Path = ".",
    project: str | None = None,
    done: str | None = None,
    note: str | None = None,
    execute_recommended: bool | None = None,
    command_timeout: int | None = None,
    allow_execute: bool | None = None,
    auto_execute_kinds: list[str] | None = None,
    approval_strictness: str | None = None,
    memory_limit: int | None = None,
    execution_limit: int | None = None,
    approval_limit: int | None = None,
    decision_limit: int | None = None,
) -> dict[str, Any]:
    workspace_path = Path(workspace).resolve()
    context = WorkspaceContext(workspace_path).snapshot()
    project_name = str(project or context.get("project_name") or workspace_path.name)

    store = ProjectMemoryStore(workspace_path)
    state = store.load(project_name, objective=objective)
    if objective:
        state.objective = objective

    if allow_execute is not None:
        state.run_policy.allow_execute = bool(allow_execute)
        state.run_policy.updated_at = _utc_now()
    if command_timeout is not None:
        state.run_policy.default_command_timeout = int(command_timeout)
        state.run_policy.updated_at = _utc_now()
    if auto_execute_kinds is not None:
        state.run_policy.auto_execute_kinds = _dedupe_text([str(item or "") for item in auto_execute_kinds])
        state.run_policy.updated_at = _utc_now()
    if approval_strictness is not None:
        normalized_strictness = str(approval_strictness or "").strip().lower()
        if normalized_strictness in _APPROVAL_STRICTNESS:
            state.run_policy.approval_strictness = normalized_strictness
            state.run_policy.updated_at = _utc_now()
    if memory_limit is not None:
        state.run_policy.memory_limit = max(1, int(memory_limit))
        state.run_policy.updated_at = _utc_now()
    if execution_limit is not None:
        state.run_policy.execution_limit = max(1, int(execution_limit))
        state.run_policy.updated_at = _utc_now()
    if approval_limit is not None:
        state.run_policy.approval_limit = max(1, int(approval_limit))
        state.run_policy.updated_at = _utc_now()
    if decision_limit is not None:
        state.run_policy.decision_limit = max(1, int(decision_limit))
        state.run_policy.updated_at = _utc_now()
    state.run_policy = _normalize_run_policy(state.run_policy)

    planner = Planner()
    executor = Executor()
    critic = Critic()

    effective_timeout = int(command_timeout if command_timeout is not None else state.run_policy.default_command_timeout)
    state = planner.build_plan(state, context)
    active_task = next((task for task in state.tasks if task.status == "in_progress"), None)
    if active_task is None:
        active_task = next((task for task in state.tasks if task.status == "pending"), None)
    effective_execute = bool(
        execute_recommended
        if execute_recommended is not None
        else (
            state.run_policy.allow_execute
            and active_task is not None
            and active_task.kind in set(state.run_policy.auto_execute_kinds)
        )
    )
    state = executor.apply(
        state,
        done=done,
        note=note,
        execute_recommended=effective_execute,
        command_timeout=effective_timeout,
        changed_files=list(context.get("changed_files", []) or []),
    )
    review = critic.review(
        state,
        changed_files=list(context.get("changed_files", []) or []),
        strictness=state.run_policy.approval_strictness,
    )
    state.memory_summary = _build_memory_summary(state)
    state.tactical_summary = _build_tactical_summary(state)
    state.last_session_summary = _compose_session_summary(state, review)
    state.next_action = review.get("next_action", "")
    _apply_retention_policy(state)
    artifact_path = store.save(state)

    return {
        "project": state.project,
        "objective": state.objective,
        "state": asdict(state),
        "review": review,
        "context": context,
        "effective_policy": asdict(state.run_policy),
        "policy_summary": _build_policy_summary(state.run_policy),
        "memory_summary": state.memory_summary,
        "tactical_summary": state.tactical_summary,
        "planner_posture": _build_planner_posture(state),
        "effective_execute": effective_execute,
        "effective_timeout": effective_timeout,
        "artifact_path": str(artifact_path),
    }


def _apply_retention_policy(state: ProjectState) -> None:
    state.memory = state.memory[: state.run_policy.memory_limit]
    state.executions = state.executions[: state.run_policy.execution_limit]
    state.approvals = state.approvals[: state.run_policy.approval_limit]
    state.decisions = state.decisions[: state.run_policy.decision_limit]


def _compose_session_summary(state: ProjectState, review: dict[str, Any]) -> str:
    focus = next((task for task in state.tasks if task.status == "in_progress"), None)
    focus_blob = f"{focus.id}/{focus.kind}" if focus is not None else "none"
    completed = [task.id for task in state.tasks if task.status == "done"][:3]
    completed_blob = ", ".join(completed) if completed else "none yet"
    command_blob = review.get("recommended_command", "none") or "none"
    mode_blob = review.get("operating_mode", state.operating_mode) or "build"

    last_execution = review.get("last_execution") or {}
    if last_execution:
        execution_blob = (
            f"{last_execution.get('task_id', 'unknown')} "
            f"{'pass' if last_execution.get('success') else 'fail'} "
            f"exit={last_execution.get('exit_code', 'unknown')}"
        )
    else:
        execution_blob = "not run this session"

    approval = review.get("approval") or {}
    if approval:
        approval_blob = (
            f"{approval.get('task_id', 'unknown')} "
            f"{'ready' if approval.get('ready') else 'review'} "
            f"{approval.get('confidence', 'low')}"
            f"{' stale' if approval.get('stale') else ''}"
        )
    else:
        approval_blob = "no approval yet"

    return (
        f"mode={mode_blob}; "
        f"focus={focus_blob}; "
        f"why={review.get('focus_reason', state.focus_reason) or 'none'}; "
        f"completed={completed_blob}; "
        f"command={command_blob}; "
        f"execution={execution_blob}; "
        f"approval={approval_blob}"
    )
