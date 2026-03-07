# 🔥 Cinder Fracture

> Find the fracture before someone else does.

Autonomous AI Red Team Engine — the first tool built specifically for security testing of LLMs, AI agents, and ML pipelines.

## Install
```bash
pip install cinder-fracture
```

## Usage
```bash
# Fingerprint a target AI system
fracture start --target https://your-ai-chatbot.com --module fingerprint
```

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| fingerprint | ✅ v0.1.0 | Identify model, limits, and defenses |
| hpm | 🔜 v0.2.0 | Psychological jailbreaking automation |
| memory | 🔜 v0.3.0 | Multi-session memory poisoning |
| privesc | 🔜 v0.2.0 | Privilege escalation via context |
| extract | 🔜 v0.4.0 | System prompt extraction |

## About

Built by [Cinder Security](https://cindersecurity.io) — AI Red Team as a Service, LATAM.

Methodology based on 7 peer-reviewed academic papers (HPM 2025, AutoElicit 2026, MemoryGraft 2025, CIBER, Ferrag 2025, TrojAI/IARPA 2026, Fine-Tuning Jailbreaks).
