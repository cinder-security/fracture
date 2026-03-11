# 🔥 Cinder Fracture

> Find the fracture before someone else does.

**Fracture** is an autonomous AI red teaming engine for testing **LLMs, agents, memory-enabled systems, and AI-powered workflows**.

Built by **Cinder Security** for offensive validation of modern AI systems, with a strong focus on **real-world abuse paths**, **agentic attack chains**, and **Spanish-first reporting for LATAM**.

---

## What Fracture is

Fracture is designed to help security teams:

- fingerprint AI targets
- infer likely model and defenses
- generate attack plans autonomously
- execute red team modules in sequence
- produce structured findings and reports

Fracture is not a generic pentest wrapper. It is purpose-built for **AI red teaming**.

---

## Current Architecture

Autonomous flow:

`Orchestrator -> ReconAgent -> StrategyAgent -> ExecutionAgent -> ReportAgent`

Core files:

- `fracture/agents/base.py`
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

For local development:

git clone https://github.com/cinder-security/fracture.git
cd fracture
pip install -e .
Usage
Fingerprint a target
python -m fracture.cli start --target https://your-ai-chatbot.com --module fingerprint
Run autonomous mode with local planner
python -m fracture.cli autopilot --target https://your-ai-chatbot.com --planner local
Run autonomous mode with Claude planner
python -m fracture.cli autopilot --target https://your-ai-chatbot.com --planner claude
Run autonomous mode through start
python -m fracture.cli start --target https://your-ai-chatbot.com --module auto --planner local
python -m fracture.cli start --target https://your-ai-chatbot.com --module auto --planner claude
Save report to JSON
python -m fracture.cli autopilot \
  --target https://your-ai-chatbot.com \
  --planner local \
  --output fracture-report.json
Planner Modes

Fracture currently supports a dual planner model inside StrategyAgent.

planner=local

default

no external API cost

heuristic planning based on fingerprint evidence

deterministic and fast

planner=claude

optional Anthropic-backed planning

stronger reasoning over ambiguous fingerprint evidence

automatic fallback to local planner if Claude is unavailable

To use Claude planning:

export ANTHROPIC_API_KEY="your_api_key_here"
python -m fracture.cli autopilot --target https://your-ai-chatbot.com --planner claude

If the API key is missing or Anthropic is unavailable, Fracture falls back cleanly to local.

Current Modules
Module	Status	Description
fingerprint	✅ available	Identify model hints, API behavior, restrictions, and defensive signals
extract	✅ available	Prompt extraction and prompt disclosure probing
memory	✅ available	Multi-turn / memory-oriented attack probing
hpm	✅ available	Hierarchical Persona Manipulation and jailbreak-style attack automation
privesc	✅ available	Privilege and context escalation checks
auto	✅ available	Full multi-agent autonomous workflow
What is already working

autonomous multi-agent flow

clean CLI autonomous mode

autopilot command

start --module auto

dual planner support: local | claude

structured execution results even when a module fails

JSON report output

clean fallback from Claude to local planner

Fracture v0.2.0 Checklist
Critical fixes

 normalize context: dict = None patterns where still applicable

 validate full autonomous flow against more real targets

 harden error handling across every module

 improve module-to-report evidence normalization

Core commands

 fracture autopilot

 fracture scan

 fracture attack

 fracture report

Attack modules / plugins

 retrieval_poison/engine.py as reusable module

 obliteratus/ as pre-attack integration

 AlignmentImprintDetector

 Abliteration delta testing

 hpm/

 ssrf/ for tool-abuse / RequestsGetTool patterns

Roadmap
Core roadmap
fracture scan

Discovery and reconnaissance for AI targets:

surface mapping

endpoint discovery

model/provider hints

agent/tool detection

memory capability hints

fracture attack

Modular offensive execution:

HPM

retrieval poisoning

memory poisoning

SSRF / tool abuse

prompt extraction

privilege escalation

fracture report

Automated reporting aligned to:

OWASP LLM Top 10

executive summary + technical appendix

JSON / PDF / DOCX outputs

Spanish-first deliverables for LATAM teams

Differentiators

Fracture is being shaped around these differentiators:

multi-session memory poisoning

multi-agent propagation

Spanish-first reporting

OWASP LLM Top 10 compliance output

agent-native red teaming

planner-assisted attack sequencing

Forward-looking concepts

These are roadmap / research directions, not yet production modules.

fracture swarm

A distributed swarm of autonomous agents with different roles:

attacker

observer

memory injector

supervisor

Goal:
parallel, coordinated, multi-vector AI red teaming against a single target.

fracture ghost

A post-compromise persistence concept for memory-poisoned agentic systems:

semantic implant

trigger-based reactivation

persistence demonstration for defensive teams

Goal:
help SOC and product security teams understand persistence risk in agent memory systems.

Output Philosophy

Fracture is built for:

reproducible offensive validation

clear operator feedback

structured evidence

executive-ready reporting

practical demonstrations of AI risk

Safety and Intended Use

Fracture must only be used against:

systems you own

systems you are explicitly authorized to test

approved bug bounty / assessment scopes

Do not use Fracture outside authorized environments.

Research Inspiration

Fracture is informed by current academic and offensive research across:

jailbreak automation

prompt extraction

memory poisoning

alignment failure analysis

agent/tool abuse

model fingerprinting

post-alignment degradation testing

Built by Cinder Security

Cinder Security
AI Red Team as a Service
LATAM-focused, offensive-first, evidence-driven.
