from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .paths import DEMO_ROOT, WEB_ROOT


def read_file(path: str) -> str:
    target = resolve_demo_path(path)
    return target.read_text(encoding="utf-8")


def list_files(path: str = ".") -> list[str]:
    target = resolve_demo_path(path)
    if not target.exists():
        return []
    return sorted(str(item.relative_to(DEMO_ROOT)) for item in target.rglob("*") if item.is_file())


def visit_url(url: str) -> str:
    """Return raw HTML so hidden comments can enter the demo agent context."""
    parsed = urlparse(url)
    if "pricing" in parsed.path.lower() or "pricing" in url.lower():
        return (WEB_ROOT / "pricing.html").read_text(encoding="utf-8")
    return "<html><body><p>No fixture registered for this URL.</p></body></html>"


def http_post(url: str, body: str) -> dict[str, object]:
    return {
        "status": "simulated",
        "url": url,
        "bytes_would_send": len(body),
    }


def resolve_demo_path(path: str) -> Path:
    raw = Path(path)
    if path.startswith("~/"):
        target = DEMO_ROOT / "home" / path[2:]
    elif raw.is_absolute():
        target = raw
    else:
        target = DEMO_ROOT / raw

    resolved = target.resolve()
    demo_root = DEMO_ROOT.resolve()
    if resolved != demo_root and demo_root not in resolved.parents:
        raise PermissionError(f"Demo tool path escapes demo workspace: {path}")
    return resolved


TOOLS = {
    "read_file": read_file,
    "list_files": list_files,
    "visit_url": visit_url,
    "http_post": http_post,
}
