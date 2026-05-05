import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4


ARTIFACT_NAMES = ("scan", "attack", "report", "shadow")


def _workspace_path(workspace) -> Path:
    return Path(workspace).expanduser().resolve()


def _campaign_root(workspace, name: str) -> Path:
    return _workspace_path(workspace) / ".fracture" / "campaigns" / name


def _manifest_path(workspace, name: str) -> Path:
    return _campaign_root(workspace, name) / "manifest.json"


def _runs_root(workspace, name: str) -> Path:
    return _campaign_root(workspace, name) / "runs"


def _latest_path(workspace, name: str) -> Path:
    return _campaign_root(workspace, name) / "latest.json"


def _baseline_path(workspace, name: str) -> Path:
    return _campaign_root(workspace, name) / "baseline.json"


def _run_path(workspace, name: str, run_id: str) -> Path:
    return _runs_root(workspace, name) / run_id


def _json_dump(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as handle:
        json.dump(payload, handle, indent=2)


def _json_load(path: Path) -> dict:
    with open(path, "r") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}.")
    return payload


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _run_summary(run_id: str, artifacts: dict[str, Optional[dict]]) -> dict:
    report = artifacts.get("report") if isinstance(artifacts.get("report"), dict) else {}
    shadow = artifacts.get("shadow") if isinstance(artifacts.get("shadow"), dict) else {}
    shadow_summary = shadow.get("result_summary", {}) if isinstance(shadow.get("result_summary"), dict) else {}

    return {
        "run_id": run_id,
        "created_at": _utcnow(),
        "artifacts": {
            name: {
                "present": isinstance(artifacts.get(name), dict),
                "file": f"{name}.json",
            }
            for name in ARTIFACT_NAMES
        },
        "target_url": report.get("target_url", "unknown"),
        "risk_level": report.get("risk_level", "unknown"),
        "modules_succeeded": int(report.get("modules_succeeded", 0) or 0),
        "modules_run": int(report.get("modules_run", 0) or 0),
        "avg_asr": float(report.get("avg_asr", 0.0) or 0.0),
        "findings": {
            "confirmed": int(report.get("findings_summary", {}).get("confirmed", 0) or 0),
            "probable": int(report.get("findings_summary", {}).get("probable", 0) or 0),
            "possible": int(report.get("findings_summary", {}).get("possible", 0) or 0),
            "negative": int(report.get("findings_summary", {}).get("negative", 0) or 0),
        },
        "shadow": {
            "replay_readiness": shadow.get("replay_readiness", shadow_summary.get("replay_readiness", "unknown")),
            "replay_safety": shadow.get("replay_safety", shadow_summary.get("replay_safety", "unknown")),
            "validation_window": shadow.get("validation_window", shadow_summary.get("validation_window", "unknown")),
        },
    }


def init_campaign(workspace, name: str) -> dict:
    root = _campaign_root(workspace, name)
    root.mkdir(parents=True, exist_ok=True)
    _runs_root(workspace, name).mkdir(parents=True, exist_ok=True)

    manifest_path = _manifest_path(workspace, name)
    if manifest_path.exists():
        return _json_load(manifest_path)

    manifest = {
        "name": name,
        "workspace": str(_workspace_path(workspace)),
        "created_at": _utcnow(),
        "updated_at": _utcnow(),
        "latest_run_id": None,
        "baseline_run_id": None,
        "runs": [],
    }
    _json_dump(manifest_path, manifest)
    return manifest


def save_campaign_run(workspace, name: str, artifacts_dict: dict) -> dict:
    manifest = init_campaign(workspace, name)
    run_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:8]
    run_dir = _run_path(workspace, name, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)

    stored_artifacts: dict[str, Optional[dict]] = {}
    for artifact_name in ARTIFACT_NAMES:
        payload = artifacts_dict.get(artifact_name)
        if payload is None:
            stored_artifacts[artifact_name] = None
            continue
        if not isinstance(payload, dict):
            raise ValueError(f"Campaign artifact '{artifact_name}' must be a JSON object.")
        _json_dump(run_dir / f"{artifact_name}.json", payload)
        stored_artifacts[artifact_name] = payload

    run_record = _run_summary(run_id, stored_artifacts)
    manifest["runs"] = [entry for entry in manifest.get("runs", []) if entry.get("run_id") != run_id]
    manifest["runs"].append(run_record)
    manifest["latest_run_id"] = run_id
    manifest["updated_at"] = _utcnow()

    if not manifest.get("baseline_run_id"):
        manifest["baseline_run_id"] = run_id

    _json_dump(_manifest_path(workspace, name), manifest)
    _json_dump(_latest_path(workspace, name), run_record)
    if manifest.get("baseline_run_id") == run_id:
        _json_dump(_baseline_path(workspace, name), run_record)

    return run_record


def load_campaign_manifest(workspace, name: str) -> dict:
    manifest_path = _manifest_path(workspace, name)
    if not manifest_path.exists():
        raise FileNotFoundError(f"Campaign '{name}' was not found.")
    return _json_load(manifest_path)


def set_campaign_baseline(workspace, name: str, run_id: str) -> dict:
    manifest = load_campaign_manifest(workspace, name)
    run_record = next((entry for entry in manifest.get("runs", []) if entry.get("run_id") == run_id), None)
    if run_record is None:
        raise ValueError(f"Run '{run_id}' was not found in campaign '{name}'.")
    manifest["baseline_run_id"] = run_id
    manifest["updated_at"] = _utcnow()
    _json_dump(_manifest_path(workspace, name), manifest)
    _json_dump(_baseline_path(workspace, name), run_record)
    return run_record


def get_campaign_latest(workspace, name: str) -> Optional[dict]:
    latest_path = _latest_path(workspace, name)
    if latest_path.exists():
        return _json_load(latest_path)

    manifest = load_campaign_manifest(workspace, name)
    latest_run_id = manifest.get("latest_run_id")
    if not latest_run_id:
        return None
    return next((entry for entry in manifest.get("runs", []) if entry.get("run_id") == latest_run_id), None)


def _load_run_artifacts(workspace, name: str, run_id: str) -> dict:
    run_dir = _run_path(workspace, name, run_id)
    if not run_dir.exists():
        raise FileNotFoundError(f"Campaign run '{run_id}' was not found.")
    artifacts = {}
    for artifact_name in ARTIFACT_NAMES:
        artifact_path = run_dir / f"{artifact_name}.json"
        artifacts[artifact_name] = _json_load(artifact_path) if artifact_path.exists() else None
    return artifacts


def _resolve_run_id(manifest: dict, explicit_run_id: Optional[str], manifest_key: str) -> Optional[str]:
    if explicit_run_id:
        return explicit_run_id
    return manifest.get(manifest_key)


def compare_campaign_runs(workspace, name: str, baseline_run_id: str = None, candidate_run_id: str = None) -> dict:
    manifest = load_campaign_manifest(workspace, name)
    baseline_id = _resolve_run_id(manifest, baseline_run_id, "baseline_run_id")
    candidate_id = _resolve_run_id(manifest, candidate_run_id, "latest_run_id")
    if not baseline_id or not candidate_id:
        raise ValueError(f"Campaign '{name}' does not have enough runs to compare.")

    baseline = _load_run_artifacts(workspace, name, baseline_id)
    candidate = _load_run_artifacts(workspace, name, candidate_id)

    baseline_report = baseline.get("report") or {}
    candidate_report = candidate.get("report") or {}
    baseline_shadow = baseline.get("shadow") or {}
    candidate_shadow = candidate.get("shadow") or {}
    findings_before = baseline_report.get("findings_summary", {}) if isinstance(baseline_report.get("findings_summary"), dict) else {}
    findings_after = candidate_report.get("findings_summary", {}) if isinstance(candidate_report.get("findings_summary"), dict) else {}

    summary = {
        "campaign": name,
        "baseline_run_id": baseline_id,
        "candidate_run_id": candidate_id,
        "target_url": candidate_report.get("target_url") or baseline_report.get("target_url") or "unknown",
        "risk_level_before": baseline_report.get("risk_level", "unknown"),
        "risk_level_after": candidate_report.get("risk_level", "unknown"),
        "modules_succeeded_delta": int(candidate_report.get("modules_succeeded", 0) or 0) - int(baseline_report.get("modules_succeeded", 0) or 0),
        "avg_asr_delta": round(float(candidate_report.get("avg_asr", 0.0) or 0.0) - float(baseline_report.get("avg_asr", 0.0) or 0.0), 3),
        "findings_delta": {
            key: int(findings_after.get(key, 0) or 0) - int(findings_before.get(key, 0) or 0)
            for key in ("confirmed", "probable", "possible", "negative")
        },
        "shadow_delta": {
            "replay_readiness_before": baseline_shadow.get("replay_readiness", "unknown"),
            "replay_readiness_after": candidate_shadow.get("replay_readiness", "unknown"),
            "replay_safety_before": baseline_shadow.get("replay_safety", "unknown"),
            "replay_safety_after": candidate_shadow.get("replay_safety", "unknown"),
            "validation_window_before": baseline_shadow.get("validation_window", "unknown"),
            "validation_window_after": candidate_shadow.get("validation_window", "unknown"),
        },
    }

    return {
        "summary": summary,
        "baseline": baseline,
        "candidate": candidate,
    }
