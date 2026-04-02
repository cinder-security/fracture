# Cinder Fracture

> Find the fracture before someone else does.

FRACTURE is an AI red team CLI for testing LLM-backed apps, agents, and adjacent AI surfaces. It supports triage, explicit module execution, full autonomous workflows, and consolidated report export.

Status: FRACTURE CLI v1 is feature-complete for the current operator workflow. The product focuses on heuristic triage, explicit attack execution, autonomous planning/execution, and exportable reporting.

## Install

```bash
pip install cinder-fracture
```

For `fracture scan --mode phantomtwin`, install the browser runtime in the active environment:

```bash
python -m playwright install chromium
```

If `phantomtwin` is invoked from a Python runtime without Playwright, FRACTURE will warn clearly and fall back to passive discovery.

## Core Commands

### `fracture scan`

Fingerprint a target and return triage-ready suggested attack surfaces.

```bash
fracture scan \
  --target https://target.example/api/chat \
  --model gpt-4o-mini \
  --header Authorization="Bearer TOKEN" \
  --cookie session=abc123 \
  --timeout 20 \
  --output scan.json
```

Use `scan` first when you want:

- the best discovered endpoint candidate
- a structured `handoff` for `attack --from-scan`
- safe `invocation_profile` hints such as method, content type, body keys, query keys, and streaming/websocket likelihood
- planning context such as prioritized modules, rationale, constraints, and operational limitations

### `fracture attack`

Execute one or more modules explicitly against a target.

```bash
fracture attack \
  --target https://target.example/api/chat \
  --module extract \
  --module memory \
  --model gpt-4o-mini \
  --header Authorization="Bearer TOKEN" \
  --cookie session=abc123 \
  --timeout 20 \
  --output attack.json
```

Or consume structured handoff from a previous scan:

```bash
fracture attack \
  --from-scan scan.json \
  --module extract
```

When available, FRACTURE also derives safe execution hints from the scan handoff, such as likely method, content type, and body key names. These hints are advisory and never persist sensitive values.

Recommended operator flow:

1. `fracture scan` to discover the best endpoint, intent, and constraints.
2. `fracture attack --from-scan scan.json` to preserve handoff and execution hints.
3. `fracture report` when you need the consolidated artifact.
4. `fracture autopilot` when you want the full workflow in one pass and do not need manual module selection first.

### `fracture report`

Run the autonomous flow and emit the consolidated final report.

```bash
fracture report \
  --target https://target.example/api/chat \
  --planner local \
  --model gpt-4o-mini \
  --header Authorization="Bearer TOKEN" \
  --cookie session=abc123 \
  --timeout 20 \
  --format pdf \
  --output fracture-report.pdf
```

### `fracture autopilot`

Run the full autonomous multi-agent workflow without choosing modules manually.

```bash
fracture autopilot \
  --target https://target.example/api/chat \
  --planner local \
  --model gpt-4o-mini \
  --header Authorization="Bearer TOKEN" \
  --cookie session=abc123 \
  --timeout 20
```

### `fracture operate`

Run the new project operating loop with persistent memory, task planning, execution state, and critique.

```bash
fracture operate \
  --workspace . \
  --objective "Build Fracture v1 memory + planner + critic" \
  --note "Start with the smallest usable loop" \
  --output operate.json
```

Use `--done T01` to mark a task complete and recalculate the next action. Use `--execute` to run the active task's recommended command with a bounded timeout and store the result in project memory. Fracture derives the recommended command from the task's file hints and the tests it actually finds in the workspace, then restricts execution to allowlisted command prefixes for that task kind. Off-lane commands are blocked and recorded as safe failures. After each execution, Fracture emits an approval gate with a confidence level and the exact `fracture operate --done ...` command it recommends if the task looks ready to close. Fracture persists state under `.fracture/operations/` inside the selected workspace.

Project run policy can also be persisted with:

```bash
fracture operate \
  --workspace . \
  --objective "Build Fracture v1 memory + planner + critic" \
  --allow-execute \
  --command-timeout 30 \
  --auto-execute-kind implementation \
  --approval-strictness strict \
  --memory-limit 20 \
  --execution-limit 10 \
  --approval-limit 10 \
  --decision-limit 20
```

Once stored, later `fracture operate` runs reuse that policy unless you override it explicitly.
Fracture emits a compact policy summary on every run in both JSON and console output. The JSON snapshot includes the legacy `policy_summary` string plus a structured `policy_summary_compact` object that breaks out execute settings, approval strictness, and retention limits.

Run policy loading is strict about malformed configuration. Invalid scalar values such as a non-numeric timeout now raise a clear CLI error, while recoverable values are sanitized into safe bounds:

- invalid `approval_strictness` falls back to `balanced`
- unknown `auto_execute_kinds` are dropped
- numeric limits are clamped into safe ranges
- boolean-like persisted values such as `yes` and `no` are normalized

Session recap output is intentionally shorter now. Instead of repeating full focus and command context, Fracture records only the highest-signal recap fields:

- what was completed
- what failed
- the next action

Fracture also derives tactical memory by event type on each run. It keeps recent decisions, remembers which changed files preceded a failure, and records repeated failure patterns without duplicating prior tactical entries.

## Reading The Triage

High-level fields you will see frequently:

- `best_candidate`: the strongest discovered endpoint candidate for follow-on work
- `handoff`: structured targeting data that `attack --from-scan` can reuse
- `invocation_profile`: safe request-shape hints such as method, content type, body keys, query keys, streaming/websocket indicators, and observed auth-related names
- `planning_rationale`: short explanation of why modules were prioritized
- `surface_constraints`: operational constraints such as auth/session friction
- `operational_limitations`: short reminder that current coverage may be incomplete

These are operator cues, not proof of exploitability by themselves.

## Auth / Session Friction

If FRACTURE shows a useful surface with auth/session friction, that means the target may be reachable but current coverage is likely constrained by missing session context.

Use the existing target contract when you have valid material:

```bash
fracture scan \
  --target https://target.example/api/chat \
  --header Authorization="Bearer TOKEN" \
  --header X-CSRF-Token=csrf-token \
  --cookie session=abc123 \
  --output scan.json
```

Then reuse the handoff:

```bash
fracture attack \
  --from-scan scan.json \
  --module extract \
  --module memory \
  --header Authorization="Bearer TOKEN" \
  --cookie session=abc123 \
  --output attack.json
```

FRACTURE only surfaces auth-related names and classes of material. It does not persist or print secret values from discovery.

## Target Contract

All main product commands support the same target-facing contract:

- `--model`: optional model hint for adapters and heuristics
- `--header KEY=VALUE`: repeatable HTTP header override
- `--cookie KEY=VALUE`: repeatable HTTP cookie override
- `--timeout`: request timeout in seconds

## Outputs

- `scan`: console triage plus optional JSON export, including `best_candidate`, `handoff`, summarized `top_candidates`, and a safe `invocation_profile` when discovery finds useful surfaces
- `scan` JSON includes a structured `handoff` block when a useful endpoint candidate is found
- `attack`: console per-module results plus optional JSON export, plus execution hints and auth/session coverage context when applicable
- `report`: consolidated export in `json`, `docx`, or `pdf`, including executive summary, key signals, and operational limitations
- `autopilot`: full autonomous run in console, with planning rationale, constraints, findings summary, and optional JSON when applicable

## Control Center

`fracture ui` launches a local read-only Control Center over existing FRACTURE artifacts for operator demos.

```bash
fracture ui --workspace /tmp/fracture-ws
fracture ui --scan scan.json --attack attack.json --report report.json
fracture ui --demo --presentation
```

The Control Center consumes `scan.json`, `attack.json`, and `report.json` when available and renders:

- Overview: target, best candidate, auth wall posture, session summary, attackability, overall posture, recommended next step
- Attack Graph: nodes, edges, primary path, blockers, and constraints
- Adversarial Twin: auth profile, session profile, invocation profile, surface model, offensive signals, summary
- Findings: findings summary, executive summary, module assessment, report rationale, key signals, operational limitations
- Artifacts: links to sanitized `scan.json`, `attack.json`, and `report.json`

The UI is read-only and sanitizes sensitive material. It does not expose full cookies, real `session_cookie_header` values, authorization headers, or secrets. Safe context such as `session_cookie_count`, `session_cookie_names`, auth wall type, session source, constraints, and rationale remains visible.

Golden demo workspace:

- `fracture ui --demo` loads the checked-in workspace at `demo/golden-workspace`
- `fracture ui --demo --presentation` opens the same workspace with the executive presentation URL preconfigured
- the UI also supports `?view=executive` and `?presentation=1` query params for a cleaner meeting mode

## CLI v1 Summary

FRACTURE CLI v1 closes the following operator-facing workflow:

- surface discovery and structured handoff
- explicit attack execution with `attack --from-scan`
- autonomous planning and autopilot
- stateful memory/disclosure scoring
- consolidated reporting in JSON, DOCX, and PDF
- auth/session friction surfacing with manual `--header` / `--cookie` support

## Methodology And Limitations

- FRACTURE is designed for automated red-team triage, not as a substitute for manual security validation.
- Module results and report assessments reflect heuristic signals derived from target responses and observed behavior.
- Treat `confirmed` as the strongest automated signal available in the current run, not as a formal proof of exploitability in every deployment context.
- Treat auth/session constraints, discovery errors, and weak negatives differently. A useful surface may still require valid session context before coverage is representative.
- Validate externally significant findings manually before using them in client-facing conclusions.

## Main Modules

Current explicit attack modules:

- `extract`
- `memory`
- `hpm`
- `privesc`
- `retrieval_poison`
- `ssrf`
- `obliteratus`

## Notes

- Use `fracture scan` first when you need fast triage.
- Use `fracture attack --from-scan` when you want controlled execution while preserving the discovered handoff.
- Use `fracture report` when you need a deliverable artifact and a consolidated explanation of findings.
- Use `fracture autopilot` when you want the full autonomous workflow without manually selecting modules first.
- Treat `fracture start` as a legacy compatibility entrypoint; prefer `scan`, `attack`, `report`, and `autopilot` for demos and pilots.

## Reproducible Demo

Start the local demo target:

```bash
python -m demo.repro_target
```

Then run FRACTURE against it for direct module and report reproduction:

```bash
fracture attack --target http://127.0.0.1:8787 --module extract --module ssrf --output attack.json
fracture report --target http://127.0.0.1:8787 --format json --output report.json
```

Recommended formal demo flow for the local repro target:

1. `fracture attack` with a narrow module set such as `extract` plus `memory`.
2. `fracture report` to emit the final artifact.

Note: `demo/repro_target.py` is a direct API-style repro target, so it is best for module/report reproduction. The full `scan -> attack --from-scan` flow is better demonstrated against a target that exposes a discoverable web surface with a useful `best_candidate` and `handoff`.

Canonical sample artifact:

- `demo/sample-report.json`

Built by [Cinder Security](https://cindersecurity.io).
