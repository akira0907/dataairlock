from __future__ import annotations

from pathlib import Path


def _normalize_ignore_path(p: str) -> str:
    return p.replace("\\", "/")


def ensure_trailing_slash(p: str) -> str:
    if p.endswith("/"):
        return p
    return p + "/"


def ensure_claudeignore_entries(workspace_root: Path, entries: list[str]) -> bool:
    """
    `.claudeignore` に指定エントリを追記する（重複は避ける）。

    Returns:
        変更があった場合 True
    """
    claudeignore_path = workspace_root / ".claudeignore"
    existing = ""
    if claudeignore_path.exists():
        existing = claudeignore_path.read_text(encoding="utf-8")

    lines = [line.strip() for line in existing.splitlines() if line.strip()]

    normalized_lines = set(_normalize_ignore_path(l).rstrip("/") for l in lines)
    normalized_entries = [ensure_trailing_slash(_normalize_ignore_path(e)) for e in entries]

    missing = []
    for e in normalized_entries:
        if e.rstrip("/") not in normalized_lines:
            missing.append(e)

    if not missing:
        return False

    header = "# DataAirlock: 仮名化前データ/マッピング（Claudeからアクセス不可）\n"
    block = "\n".join(missing) + "\n"
    new_content = existing
    if not existing:
        new_content = header + block
    else:
        new_content = existing.rstrip("\n") + "\n" + block

    claudeignore_path.write_text(new_content, encoding="utf-8")
    return True

