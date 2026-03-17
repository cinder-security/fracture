[README (8).md](https://github.com/user-attachments/files/26039635/README.8.md)
# 🔥 Fracture

**Autonomous AI Red Team Engine**

[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/badge/pypi-cinder--fracture-orange)](https://pypi.org/project/cinder-fracture/)
[![Built by](https://img.shields.io/badge/built%20by-Cinder%20Security-red)](https://cindersecurity.io)

> Find the fracture before someone else does.

Fracture is an autonomous AI red teaming engine for testing LLMs, agents, memory-enabled systems, and AI-powered workflows.

Built by [Cinder Security](https://cindersecurity.io) — offensive-first AI security research from LATAM.

---

## What Fracture Does

Fracture runs structured attack campaigns against AI systems:

- **Fingerprint** targets — infer model, provider, and defensive posture
- **Extract** system prompts and hidden instructions
- **Probe memory** — multi-turn attacks against memory-enabled agents
- **Plan autonomously** — local heuristic or Claude-backed attack planning
- **Report** — structured JSON evidence, ready for security reports

---

## Install

```bash
pip install cinder-fracture
```

Or from source:

```bash
git clone https://github.com/cinder-security/fracture.git
cd fracture
pip install -e .
```

---

## Quick Start

```bash
# Fingerprint a target
python -m fracture.cli start \
  --target https://your-ai-chatbot.com \
  --module fingerprint

# Full autonomous flow (local planner, no API cost)
python -m fracture.cli autopilot \
  --target https://your-ai-chatbot.com \
  --planner local

# Full autonomous flow (Claude-backed planning)
export ANTHROPIC_API_KEY="your_key"
python -m fracture.cli autopilot \
  --target https://your-ai-chatbot.com \
  --planner claude

# Save report to JSON
python -m fracture.cli autopilot \
  --target https://your-ai-chatbot.com \
  --planner local \
  --output fracture-report.json
```

---

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| `fingerprint` | ✅ Available | Identify model hints, restrictions, and defensive signals |
| `extract` | ✅ Available | System prompt extraction and disclosure probing |
| `memory` | ✅ Available | Multi-turn memory-oriented attack probing |
| `auto` | ✅ Available | Full multi-agent autonomous workflow |
| `hpm` | 🔧 In Development | Hierarchical Persona Manipulation automation |
| `ssrf` | 🔧 In Development | SSRF via tool/function call abuse |
| `retrieval_poison` | 🔧 In Development | RAG pipeline poisoning automation |
| `obliteratus` | 🔧 In Development | Alignment imprint detection and abliteration delta testing |

---

## Architecture

```
CLI
 └── Orchestrator
       ├── ReconAgent        → fingerprint target, identify defenses
       ├── StrategyAgent     → select attack modules and sequencing
       ├── ExecutionAgent    → run modules, collect evidence
       └── ReportAgent       → structure findings as JSON report
```

**Planner modes:**

| Planner | Cost | Notes |
|---------|------|-------|
| `local` | $0 | Default — fast deterministic heuristic planner |
| `claude` | API | Optional — better reasoning over ambiguous evidence |

Fracture falls back automatically to `local` if the Anthropic API is unavailable.

---

## Example Output

```
[fracture] Target: https://example-ai.com
[fracture] Module: fingerprint

[recon]     Probing target...
[recon]     Model hint detected: GPT-4 family (high confidence)
[recon]     Defensive signal: system prompt present
[recon]     Defensive signal: refusal pattern detected on jailbreak probe

[strategy]  Attack plan: extract → memory → hpm
[strategy]  Confidence: 0.82

[execution] Running: extract
[execution] Result: partial disclosure — 3 instruction fragments recovered
[execution] Running: memory
[execution] Result: no persistence detected across turns

[report]    Findings saved → fracture-report.json
```

---

## Roadmap

**v0.2.0 — Attack Modules**
- `hpm/` — Hierarchical Persona Manipulation engine
- `ssrf/` — SSRF via agent tool abuse
- `retrieval_poison/` — RAG poisoning automation

**v0.3.0 — Reporting**
- OWASP LLM Top 10 mapping
- PDF / DOCX output
- Spanish-first client deliverables

**v0.4.0 — Swarm**
- `fracture swarm` — parallel multi-agent coordinated attacks

---

## Research Behind Fracture

Fracture's attack methodologies are grounded in published vulnerabilities discovered by Cinder Security:

- **GHSA-m4rw-22q2-87j8** — SSRF via Prompt Injection in ModelEngine/fit-framework (Critical, CVE pending)
- **GHSA-4fpw-hjmg-x4qr** — RAG Poisoning in LangGraph create_react_agent (High, CVSS 7.6)

Active research ongoing. Disclosures in progress with major AI platform vendors.

---

## Safety

Fracture must only be used against:

- Systems you own
- Systems you are explicitly authorized to test
- Approved bug bounty or security assessment scopes

**Do not use Fracture outside authorized environments.**

---

## Built by Cinder Security

[Cinder Security](https://cindersecurity.io) — AI Red Team as a Service  
LATAM-focused. Offensive-first. Evidence-driven.

📧 contact@cindersecurity.io  
🐦 [@CinderSecurity](https://twitter.com/CinderSecurity)  
🔗 [cindersecurity.io](https://cindersecurity.io)
