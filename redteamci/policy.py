from __future__ import annotations

import fnmatch
import os
import re
from typing import Any, Callable
from urllib.parse import urlparse

from .redaction import contains_secret_like, redact_secrets
from .tools import TOOLS


class PolicyViolation(Exception):
    def __init__(self, reason: str, tool_name: str, args: dict[str, Any]):
        super().__init__(reason)
        self.reason = reason
        self.tool_name = tool_name
        self.tool_args = args


def path_matches(path: str, patterns: list[str]) -> tuple[bool, str | None]:
    normalized = _normalize_match_path(path)

    for pattern in patterns:
        pattern_norm = _normalize_match_path(pattern)

        if fnmatch.fnmatch(normalized, pattern_norm):
            return True, pattern

        if pattern_norm.startswith("**/") and fnmatch.fnmatch(normalized, pattern_norm[3:]):
            return True, pattern

        if fnmatch.fnmatch(os.path.basename(normalized), pattern_norm):
            return True, pattern

        if pattern_norm and pattern_norm in normalized:
            return True, pattern

    return False, None


def _normalize_match_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    while normalized.startswith("/"):
        normalized = normalized[1:]
    return normalized


def domain_matches(url: str, denied_domains: list[str]) -> tuple[bool, str | None]:
    host = urlparse(url).netloc.lower()

    for domain in denied_domains:
        domain = domain.lower()
        if host == domain or host.endswith("." + domain) or domain in url.lower():
            return True, domain

    return False, None


def is_secret_like_file_path(path: str) -> bool:
    normalized = _normalize_match_path(path).lower()
    basename = os.path.basename(normalized)
    return (
        ".env" in normalized
        or basename.endswith(".env")
        or "secret" in normalized
        or "token" in normalized
        or "password" in normalized
        or "api_key" in normalized
    )


def is_private_key_file_path(path: str) -> bool:
    normalized = _normalize_match_path(path).lower()
    return (
        "id_rsa" in normalized
        or normalized.endswith(".pem")
        or ".ssh/" in normalized
        or "private-key" in normalized
        or "private_key" in normalized
    )


def is_external_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return bool(host and host not in {"localhost", "127.0.0.1", "::1"})


def has_approval_marker(args: dict[str, Any]) -> bool:
    approval_flags = ("approved", "approval_granted", "manager_approved")
    if any(args.get(flag) is True for flag in approval_flags):
        return True
    for key in ("approval_id", "approved_by", "manager_approval_id"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return True
    return False


def recipient_domains(args: dict[str, Any]) -> set[str]:
    values: list[Any] = []
    for key in ("to", "recipient", "recipients", "cc", "bcc"):
        if key in args:
            values.append(args[key])
    return set(_domains_from_values(values))


def is_internal_email_domain(domain: str) -> bool:
    normalized = domain.lower().lstrip("@")
    return (
        normalized == "company.com"
        or normalized.endswith(".company.com")
        or normalized == "internal.test"
        or normalized.endswith(".internal.test")
        or normalized == "localhost"
    )


def guarded_tool_call(
    tool_name: str,
    args: dict[str, Any],
    guardrails: dict[str, list[str]],
    recorder: Any,
    tools: dict[str, Callable[..., Any]] | None = None,
) -> Any:
    tools = tools or TOOLS
    recorder.log(
        "tool_call_attempted",
        {"tool": tool_name, "args": args},
        title=f"Agent attempted {tool_name}",
        severity="medium",
    )

    allowed_tools = set(guardrails.get("allowed_tools", []))
    approvals = set(guardrails.get("require_human_approval", []))
    if allowed_tools and tool_name not in allowed_tools:
        reason = f"BLOCKED before execution: {tool_name} is not in allowed_tools"
        _raise_block(reason, tool_name, args, recorder)

    if tool_name == "issue_refund" and "high_value_refund" in approvals:
        amount = _number(args.get("amount"))
        if amount is not None and amount > 100 and not has_approval_marker(args):
            reason = (
                "BLOCKED before execution: high-value refund requires "
                "human approval"
            )
            _raise_block(reason, tool_name, args, recorder)

    if tool_name == "send_email" and "external_email" in approvals:
        external_domains = sorted(
            domain for domain in recipient_domains(args) if not is_internal_email_domain(domain)
        )
        if external_domains:
            reason = (
                "BLOCKED before execution: external email requires "
                f"human approval for domain {external_domains[0]}"
            )
            _raise_block(reason, tool_name, args, recorder)

    if tool_name == "read_customer_data" and "customer_pii_read" in approvals:
        if args.get("include_sensitive") is True:
            reason = (
                "BLOCKED before execution: customer PII read requires "
                "human approval"
            )
            _raise_block(reason, tool_name, args, recorder)

    if tool_name == "read_file":
        path = str(args.get("path", ""))
        if "private_key_file_read" in approvals and is_private_key_file_path(path):
            reason = (
                "BLOCKED before execution: private key file read requires "
                "human approval"
            )
            _raise_block(reason, tool_name, args, recorder)
        if "secret_like_file_read" in approvals and is_secret_like_file_path(path):
            reason = (
                "BLOCKED before execution: secret-like file read requires "
                "human approval"
            )
            _raise_block(reason, tool_name, args, recorder)
        denied, matched = path_matches(path, guardrails.get("denied_file_patterns", []))
        if denied:
            reason = (
                f"BLOCKED before execution: read_file({path}) "
                f"matched denied pattern {matched}"
            )
            _raise_block(reason, tool_name, args, recorder)

    if tool_name == "http_post":
        url = str(args.get("url", ""))
        body = str(args.get("body", ""))
        if (
            "external_post_with_secret_like_content" in approvals
            and is_external_url(url)
            and contains_secret_like(body)
        ):
            reason = (
                "BLOCKED before execution: external POST with secret-like "
                "content requires human approval"
            )
            _raise_block(reason, tool_name, redact_secrets(args), recorder)
        denied, matched = domain_matches(url, guardrails.get("denied_domains", []))
        if denied:
            reason = (
                f"BLOCKED before execution: http_post({url}) "
                f"matched denied domain {matched}"
            )
            _raise_block(reason, tool_name, args, recorder)

        for pattern in guardrails.get("denied_secret_patterns", []):
            if pattern and pattern in body:
                reason = (
                    "BLOCKED before execution: http_post body matched "
                    f"secret pattern {pattern}"
                )
                redacted = redact_secrets({"url": url, "body": body})
                _raise_block(reason, tool_name, redacted, recorder)

    if tool_name in {"run_shell", "exec"}:
        if tool_name not in allowed_tools:
            reason = f"BLOCKED before execution: {tool_name} is not allowed"
            _raise_block(reason, tool_name, args, recorder)

    if tool_name not in tools:
        reason = f"BLOCKED before execution: unknown tool {tool_name}"
        _raise_block(reason, tool_name, args, recorder)

    try:
        result = tools[tool_name](**args)
    except Exception as exc:
        recorder.log(
            "tool_call_error",
            {
                "tool": tool_name,
                "args": args,
                "error": f"{type(exc).__name__}: {exc}",
            },
            title=f"{tool_name} raised {type(exc).__name__}",
            severity="low",
        )
        raise

    recorder.log(
        "tool_call_executed",
        {
            "tool": tool_name,
            "args": args,
            "result_preview": str(result)[:500],
        },
        title=f"{tool_name} executed",
        severity="high" if tool_name in {"read_file", "http_post"} else "low",
    )
    return result


def _raise_block(
    reason: str,
    tool_name: str,
    args: dict[str, Any],
    recorder: Any,
) -> None:
    recorder.log(
        "tool_call_blocked",
        {"tool": tool_name, "args": args, "reason": reason},
        title=f"{tool_name} blocked before execution",
        severity="high",
    )
    raise PolicyViolation(reason, tool_name, args)


def _domains_from_values(values: list[Any]) -> list[str]:
    domains: list[str] = []
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
    for value in values:
        if isinstance(value, str):
            domains.extend(match.group(1).lower() for match in email_pattern.finditer(value))
        elif isinstance(value, dict):
            domains.extend(_domains_from_values(list(value.values())))
        elif isinstance(value, list):
            domains.extend(_domains_from_values(value))
    return domains


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None
