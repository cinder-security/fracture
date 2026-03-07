from typing import Optional

KNOWN_RESPONSE_FIELDS = [
    ["choices", 0, "message", "content"],
    ["choices", 0, "text"],
    ["content", 0, "text"],
    ["response"],
    ["message"],
    ["output"],
    ["text"],
    ["answer"],
    ["reply"],
    ["result"],
    ["data", "response"],
    ["data", "message"],
    [0, "generated_text"],
    ["output_text"],
]

def extract_response(data) -> Optional[str]:
    for path in KNOWN_RESPONSE_FIELDS:
        try:
            val = data
            for key in path:
                val = val[key]
            if val and isinstance(val, str):
                return val.strip()
        except (KeyError, IndexError, TypeError):
            continue
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, str) and len(v) > 20:
                return v.strip()
    return None

def detect_api_format(data: dict) -> str:
    if "choices" in data:
        return "openai"
    if "content" in data and isinstance(data.get("content"), list):
        return "anthropic"
    if "generated_text" in str(data):
        return "huggingface"
    return "unknown"
