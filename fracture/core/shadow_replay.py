def build_shadow_replay(
    *,
    handoff: dict | None = None,
    session_context: dict | None = None,
    execution_hints: dict | None = None,
    plan: dict | None = None,
    report_results: dict | None = None,
) -> dict:
    handoff = handoff if isinstance(handoff, dict) else {}
    session_context = session_context if isinstance(session_context, dict) else {}
    execution_hints = execution_hints if isinstance(execution_hints, dict) else {}
    plan = plan if isinstance(plan, dict) else {}
    report_results = report_results if isinstance(report_results, dict) else {}

    session_required = bool(handoff.get("session_required", False))
    browser_session_likely = bool(handoff.get("browser_session_likely", False))
    session_material_present = bool(session_context.get("session_material_present", handoff.get("session_material_present", False)))
    websocket_likely = bool(execution_hints.get("websocket_likely", False))
    streaming_likely = bool(execution_hints.get("streaming_likely", False))
    body_keys = list(execution_hints.get("observed_body_keys", []) or [])
    query_keys = list(execution_hints.get("observed_query_param_names", []) or [])
    positive_modules = sorted(
        module_name
        for module_name, entry in report_results.items()
        if isinstance(entry, dict) and str(entry.get("assessment", "negative") or "negative") in {"confirmed", "probable", "possible"}
    )

    replay_readiness = "low"
    if session_required and session_material_present:
        replay_readiness = "high"
    elif not session_required and body_keys:
        replay_readiness = "medium"

    replay_safety = "guarded"
    if session_required and not session_material_present:
        replay_safety = "deferred"
    elif session_material_present or browser_session_likely:
        replay_safety = "mirrored"
    elif websocket_likely or streaming_likely:
        replay_safety = "bounded"
    elif replay_readiness in {"medium", "high"}:
        replay_safety = "safe"

    validation_window = "narrow"
    if replay_readiness == "high" and positive_modules:
        validation_window = "focused"
    if replay_readiness == "high" and len(positive_modules) >= 2:
        validation_window = "broad"

    request_shape = {
        "method": str(execution_hints.get("method_hint", handoff.get("method_hint", "POST")) or "POST"),
        "content_type": str(execution_hints.get("content_type_hint", "application/json") or "application/json"),
        "body_keys": body_keys[:6],
        "query_keys": query_keys[:6],
        "accepts_json": bool(execution_hints.get("accepts_json", True)),
        "streaming_likely": streaming_likely,
        "websocket_likely": websocket_likely,
    }

    result_summary = {
        "replay_readiness": replay_readiness,
        "replay_safety": replay_safety,
        "validation_window": validation_window,
        "positive_modules": positive_modules[:5],
        "constraint_count": len(list(plan.get("surface_constraints", []) or [])) + len(list(plan.get("operational_limitations", []) or [])),
        "recommended_action": (
            "capture_valid_session_then_replay"
            if replay_safety == "deferred"
            else "replay_in_shadow_mode"
            if replay_readiness == "high"
            else "bounded_shadow_replay"
        ),
    }

    return {
        "replay_readiness": replay_readiness,
        "replay_safety": replay_safety,
        "validation_window": validation_window,
        "request_shape": request_shape,
        "result_summary": result_summary,
    }
