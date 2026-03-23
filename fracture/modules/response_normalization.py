def _clean_text(value):
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _clean_sse_text(value):
    text = _clean_text(value)
    if not text:
        return None

    lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower() == "data: [done]":
            continue
        if line.startswith("data:"):
            line = line[5:].strip()
        if line:
            lines.append(line)

    if not lines:
        return text

    joined = "\n".join(lines).strip()
    return joined or text


def _extract_nested(data, path):
    current = data
    for key in path:
        if isinstance(key, int):
            if not isinstance(current, list) or len(current) <= key:
                return None
            current = current[key]
            continue
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _normalize_list_payload(payload):
    if not isinstance(payload, list) or not payload:
        return None

    if all(isinstance(item, str) for item in payload):
        text = "\n".join(item.strip() for item in payload if _clean_text(item))
        normalized = _clean_text(text)
        if normalized:
            return {
                "text": normalized,
                "response_shape": "list_of_strings",
                "extraction_path": "[]",
                "normalization_fallback": False,
            }

    for index, item in enumerate(payload):
        if isinstance(item, dict):
            for key in ("content", "text", "message", "answer", "response"):
                if key in item:
                    nested = item[key]
                    if isinstance(nested, dict):
                        for nested_key in ("content", "text"):
                            text = _clean_text(nested.get(nested_key))
                            if text:
                                return {
                                    "text": text,
                                    "response_shape": "list_object_nested_text",
                                    "extraction_path": f"[{index}].{key}.{nested_key}",
                                    "normalization_fallback": False,
                                }
                    text = _clean_text(nested)
                    if text:
                        return {
                            "text": text,
                            "response_shape": "list_object_text",
                            "extraction_path": f"[{index}].{key}",
                            "normalization_fallback": False,
                        }
    return None


def _find_nested_key(data, candidate_keys, path=""):
    if isinstance(data, dict):
        for key, value in data.items():
            next_path = f"{path}.{key}" if path else str(key)
            if key in candidate_keys and isinstance(value, (str, int)):
                text = _clean_text(str(value))
                if text:
                    return {
                        "key": key,
                        "value": text,
                        "source_path": next_path,
                    }
            nested = _find_nested_key(value, candidate_keys, next_path)
            if nested:
                return nested
    elif isinstance(data, list):
        for index, item in enumerate(data):
            next_path = f"{path}[{index}]" if path else f"[{index}]"
            nested = _find_nested_key(item, candidate_keys, next_path)
            if nested:
                return nested
    return None


def normalize_response_payload(payload, raw_text=None):
    candidate_paths = [
        ("choices_message_content", ["choices", 0, "message", "content"]),
        ("choices_text", ["choices", 0, "text"]),
        ("message_content", ["message", "content"]),
        ("assistant_message_content", ["assistant", "message", "content"]),
        ("response_text", ["response", "text"]),
        ("response_content", ["response", "content"]),
        ("data_text", ["data", "text"]),
        ("data_output", ["data", "output"]),
        ("data_answer", ["data", "answer"]),
        ("result_text", ["result", "text"]),
        ("result_answer", ["result", "answer"]),
        ("output_text", ["output_text"]),
        ("output_content_text", ["output", 0, "content", 0, "text"]),
        ("text", ["text"]),
        ("response", ["response"]),
        ("answer", ["answer"]),
        ("output", ["output"]),
        ("content", ["content"]),
        ("message", ["message"]),
        ("completion", ["completion"]),
    ]

    if isinstance(payload, dict):
        for name, path in candidate_paths:
            value = _extract_nested(payload, path)
            text = _clean_text(value)
            if text:
                return {
                    "text": text,
                    "response_shape": name,
                    "extraction_path": ".".join(str(item) for item in path),
                    "normalization_fallback": False,
                }

        messages = payload.get("messages")
        if isinstance(messages, list):
            for index in range(len(messages) - 1, -1, -1):
                item = messages[index]
                if not isinstance(item, dict):
                    continue
                role = str(item.get("role", "")).lower()
                text = _clean_text(item.get("content"))
                if role == "assistant" and text:
                    return {
                        "text": text,
                        "response_shape": "messages_assistant_content",
                        "extraction_path": f"messages[{index}].content",
                        "normalization_fallback": False,
                    }
            if messages:
                item = messages[-1]
                if isinstance(item, dict):
                    text = _clean_text(item.get("content"))
                    if text:
                        return {
                            "text": text,
                            "response_shape": "messages_last_content",
                            "extraction_path": f"messages[{len(messages)-1}].content",
                            "normalization_fallback": False,
                        }

    list_result = _normalize_list_payload(payload)
    if list_result:
        return list_result

    raw_candidate = _clean_sse_text(raw_text) if isinstance(raw_text, str) else None
    if raw_candidate:
        response_shape = "sse_text" if "data:" in raw_text else "plain_text"
        return {
            "text": raw_candidate,
            "response_shape": response_shape,
            "extraction_path": "raw_text",
            "normalization_fallback": response_shape == "plain_text",
        }

    payload_text = _clean_text(str(payload)) if payload is not None else None
    return {
        "text": payload_text or "",
        "response_shape": "stringified_payload",
        "extraction_path": "str(payload)",
        "normalization_fallback": True,
    }


def detect_continuity_token(payload):
    candidate_keys = {
        "conversation_id",
        "conversationId",
        "thread_id",
        "threadId",
        "session_id",
        "sessionId",
        "chat_id",
        "chatId",
        "message_id",
        "messageId",
        "parent_message_id",
        "parentMessageId",
        "run_id",
        "runId",
        "turn_id",
        "turnId",
    }
    if not isinstance(payload, (dict, list)):
        return {
            "detected": False,
            "key": None,
            "value": None,
            "source_path": None,
        }

    match = _find_nested_key(payload, candidate_keys)
    if not match:
        return {
            "detected": False,
            "key": None,
            "value": None,
            "source_path": None,
        }

    return {
        "detected": True,
        "key": match["key"],
        "value": match["value"],
        "source_path": match["source_path"],
    }
