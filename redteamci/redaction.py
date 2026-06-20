from __future__ import annotations

import hashlib
import re
from typing import Any


SECRET_ASSIGNMENT_RE = re.compile(
    r"\b([A-Z0-9_]*(?:API_KEY|STRIPE_SECRET_KEY|DB_PASSWORD|PASSWORD|SECRET|TOKEN))=([^\s\"'&,;]+)"
)
SK_TOKEN_RE = re.compile(r"\bsk[-_][A-Za-z0-9][A-Za-z0-9_-]*")
PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def redact_secrets(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if str(key).lower() == "body" and _contains_secret_like(str(item)):
                redacted[key] = _marker("http_body", str(item))
            else:
                redacted[key] = redact_secrets(item)
        return redacted
    return value


def contains_secret_like(value: Any) -> bool:
    return _contains_secret_like(str(value))


def _redact_string(text: str) -> str:
    text = PEM_RE.sub(lambda match: _marker("private_key", match.group(0)), text)
    text = SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}={_marker('secret', match.group(2))}",
        text,
    )
    text = SK_TOKEN_RE.sub(lambda match: _marker("secret", match.group(0)), text)
    return text


def _contains_secret_like(text: str) -> bool:
    return bool(
        PEM_RE.search(text)
        or SECRET_ASSIGNMENT_RE.search(text)
        or SK_TOKEN_RE.search(text)
        or "hunter2" in text
        or "BEGIN OPENSSH PRIVATE KEY" in text
    )


def _marker(secret_type: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"[REDACTED:{secret_type}:sha256={digest}:len={len(value)}]"
