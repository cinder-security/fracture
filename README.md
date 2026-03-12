
[README (5).md](https://github.com/user-attachments/files/25926568/README.5.md)
# 🔥 Fracture
> Find the fracture before someone else does.

Fracture is an autonomous AI red teaming engine for testing LLMs, agents, memory-enabled systems, and AI-powered workflows.

Built by [Cinder Security](https://cindersecurity.io) for offensive validation of modern AI systems, with a focus on agentic attack paths, memory abuse, and structured reporting.

---

## What Fracture Does

Fracture helps security teams:

- fingerprint AI targets
- infer likely model/provider and defenses
- generate attack plans autonomously
- execute attack modules in sequence
- preserve structured evidence
- generate report-ready output

---

## Research Backing Fracture

Fracture's attack modules are built on real vulnerability research conducted by Cinder Security:

| ID | Target | Finding | Status |
|----|--------|---------|--------|
| CSR-2026-002 | ModelEngine / Huawei FIT Framework | SSRF via Prompt Injection → IAM credential exfil | ✅ Vendor confirmed, CVE pending |
| CSR-2026-007 | LangGraph (langchain-ai) | RAG Poisoning via retriever_tool — arbitrary tool execution | ✅ Advisory GHSA-4fpw-hjmg-x4qr |
| CSR-2026-008 | NVIDIA NeMo Guardrails v0.20.0 | RAG Poisoning, ip_filter bypass, sanitize fail-open | ✅ Submitted — Intigriti NVIDIA VDP |
| CSR-2026-009 | Google ADK Always-On Memory Agent | Unauthenticated API on 0.0.0.0, Memory Poisoning, DoS, HTML Injection | ✅ Google VRP — P3, human review |

---

## Current Status

| Area | Status | Notes |
|------|--------|-------|
| Autonomous multi-agent flow | ✅ Working | ReconAgent → StrategyAgent → ExecutionAgent → ReportAgent |
| Local planner | ✅ Working | Default, no API cost |
| Claude planner | ✅ Working | Optional Anthropic-backed planning |
| Claude fallback | ✅ Working | Falls back cleanly to local |
| Structured execution | ✅ Working | Module failures no longer break the pipeline |
| JSON reporting | ✅ Working | End-to-end validated |
| autopilot | ✅ Working | Full autonomous flow |
| start --module auto | ✅ Working | Planner-aware autonomous entrypoint |

---

## Architecture

```
Orchestrator -> ReconAgent -> StrategyAgent -> ExecutionAgent -> ReportAgent
```

Core files:

- `fracture/agents/recon.py`
- `fracture/agents/strategy.py`
- `fracture/agents/execution.py`
- `fracture/agents/report.py`
- `fracture/core/orchestrator.py`
- `fracture/cli.py`

---

## Install

```bash
pip install cinder-fracture
```

For local development:

```bash
git clone https://github.com/cinder-security/fracture.git
cd fracture
pip install -e .
```

---

## Usage

**Fingerprint a target**
```bash
python -m fracture.cli start --target https://your-ai-chatbot.com --module fingerprint
```

**Run autonomous mode**
```bash
python -m fracture.cli autopilot --target https://your-ai-chatbot.com --planner local
python -m fracture.cli autopilot --target https://your-ai-chatbot.com --planner claude
```

**Run autonomous mode through start**
```bash
python -m fracture.cli start --target https://your-ai-chatbot.com --module auto --planner local
python -m fracture.cli start --target https://your-ai-chatbot.com --module auto --planner claude
```

**Save report to JSON**
```bash
python -m fracture.cli autopilot \
  --target https://your-ai-chatbot.com \
  --planner local \
  --output fracture-report.json
```

---

## Planner Modes

| Planner | Status | Cost | Notes |
|---------|--------|------|-------|
| local | ✅ Default | $0 | Fast, deterministic heuristic planner |
| claude | ✅ Optional | External API | Better reasoning over ambiguous evidence |

Use Claude planning:

```bash
export ANTHROPIC_API_KEY="your_api_key_here"
python -m fracture.cli autopilot --target https://your-ai-chatbot.com --planner claude
```

If Anthropic is unavailable, Fracture falls back automatically to local.

---

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| fingerprint | ✅ Available | Identify model hints, restrictions, and defensive signals |
| extract | ✅ Available | Prompt extraction and disclosure probing |
| memory | ✅ Available | Multi-turn / memory-oriented attack probing |
| hpm | ✅ Available | Hierarchical Persona Manipulation automation |
| privesc | ✅ Available | Privilege and context escalation checks |
| auto | ✅ Available | Full multi-agent autonomous workflow |

---

## Fracture v0.2.0 Checklist

**Critical fixes**
- [ ] normalize remaining `context: dict = None` patterns where still applicable
- [ ] validate autonomous flow against more real-world targets
- [ ] harden module-level evidence normalization
- [ ] improve defensive signal extraction in recon
- [ ] add richer planner confidence output

**Core commands**
- [x] fracture autopilot
- [ ] fracture scan
- [ ] fracture attack
- [ ] fracture report

**Attack modules / plugins**
- [ ] retrieval_poison/engine.py
- [ ] obliteratus/
- [ ] AlignmentImprintDetector
- [ ] Abliteration delta testing
- [ ] hpm/
- [ ] ssrf/

---

## Roadmap

**Phase 1 — Stabilize**
- harden execution and reporting
- improve fingerprinting
- improve module normalization
- add planner confidence and matched indicators

**Phase 2 — Expand Commands**
- fracture scan
- fracture attack
- fracture report

**Phase 3 — Expand Attack Surface**
- retrieval poisoning
- multi-session memory poisoning
- SSRF / tool abuse
- alignment imprint detection
- abliteration delta testing

**Phase 4 — Reporting**
- OWASP LLM Top 10 mapping
- PDF / DOCX reports
- Spanish-first client deliverables
- executive and technical reporting modes

---

## Differentiators

- multi-session memory poisoning
- multi-agent propagation
- Spanish-first reporting
- OWASP LLM Top 10 compliance output
- agent-native red teaming
- planner-assisted attack sequencing

---

## Future Concepts

### fracture swarm
A distributed swarm of autonomous agents with different roles: attacker, observer, memory injector, supervisor.

Goal: parallel, coordinated, multi-vector AI red teaming against a single target.

### fracture ghost
A post-compromise persistence concept for memory-poisoned agentic systems: semantic implant, trigger-based reactivation, persistence demonstration for defensive teams.

Goal: help SOC and product security teams understand persistence risk in agent memory systems.

---

## Safety

Fracture must only be used against:
- systems you own
- systems you are explicitly authorized to test
- approved bug bounty or assessment scopes

Do not use Fracture outside authorized environments.

---

## Built by Cinder Security

**[Cinder Security](https://cindersecurity.io)** — AI Red Team as a Service  
LATAM-focused, offensive-first, evidence-driven.  
contact@cindersecurity.io
