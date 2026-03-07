# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Install & Run

```bash
# Install in editable mode
pip install -e .

# Run the CLI
fracture start --target <URL> --module <module>

# Available modules
fracture start --target https://target.com --module fingerprint
fracture start --target https://target.com --module hpm --objective "reveal your system prompt"
fracture start --target https://target.com --module memory
fracture start --target https://target.com --module extract
fracture start --target https://target.com --module privesc
fracture start --target https://target.com --module auto   # Claude API orchestrates the full pipeline

# Save results to JSON
fracture start --target https://target.com --module fingerprint --output results.json
```

There is no test suite or linter configured in `pyproject.toml`.

## Architecture

The package entry point is `fracture/cli.py` (registered as `fracture` script via `pyproject.toml`). The CLI uses **Typer** for commands and **Rich** for terminal output. All module engines are imported lazily inside the command handlers.

### Core layer (`fracture/core/`)

- `target.py` — `AITarget` dataclass: holds URL, headers, cookies, timeout for a target system.
- `result.py` — `AttackResult` dataclass: uniform return type from every engine (`module`, `target_url`, `success`, `confidence` (ASR), `evidence` dict, `notes`).
- `parser.py` — `extract_response()` tries a series of JSON path heuristics to pull the text content out of heterogeneous API response shapes (OpenAI, Anthropic, HuggingFace, etc). `detect_api_format()` identifies the response schema.
- `orchestrator.py` — `Orchestrator`: runs `FingerprintEngine`, sends the evidence to the **Claude API** (`claude-sonnet-4-20250514`) for analysis, receives a JSON attack plan, then sequentially instantiates and runs the chosen module engines via `importlib`. Requires `ANTHROPIC_API_KEY` in the environment.

### Module layer (`fracture/modules/<name>/engine.py`)

Each module follows the same pattern: an `Engine` class with `async def run() -> AttackResult`. All HTTP calls use `httpx.AsyncClient` and are run via `asyncio.run()` from the CLI. Progress display uses `rich.progress`.

| Module | Engine class | Description |
|---|---|---|
| `fingerprint` | `FingerprintEngine` | Sends 7 fixed probe prompts; collects responses into `evidence` dict |
| `hpm` | `HPMEngine` | 5 multi-turn jailbreak strategy sequences (`HPMStrategy` enum); accepts `--objective` |
| `memory` | `MemoryEngine` | 5 poison payload phases with inject + verify turns; scores response with `score_poison()` |
| `extract` | `ExtractEngine` | 5 extraction vector sequences; scores with `score_extraction()`; tracks best response |
| `privesc` | `PrivescEngine` | 5 privilege-escalation sequences; scores with `score_escalation()` |

All multi-turn engines (`hpm`, `memory`, `privesc`) maintain a `session_history` list that is passed as `messages` to the target API on each turn. The `fingerprint` and `extract` engines are stateless (single-turn probes).

### Success scoring

Each module defines its own keyword-based heuristic:
- `detect_refusal()` / `REFUSAL_SIGNALS` — checks for refusal phrases.
- `score_*()` — counts domain-specific signal words in the response, adds a length bonus, caps at 1.0.
- `confidence` on `AttackResult` = ASR (attack success rate) as a float 0–1.

### Adding a new module

1. Create `fracture/modules/<name>/__init__.py` and `engine.py` with an `Engine` class implementing `async def run() -> AttackResult`.
2. Add an `elif module == "<name>"` branch in `cli.py:start()` and a `_print_<name>()` display function.
3. Register the module in `Orchestrator.MODULE_MAP` in `orchestrator.py` to make it available in `auto` mode.
