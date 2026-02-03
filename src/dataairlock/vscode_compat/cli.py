from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from dataairlock.vscode_compat.anonymizer import Anonymizer
from dataairlock.vscode_compat.file_processor import DEFAULT_EXTENSIONS, FileProcessor
from dataairlock.vscode_compat.ignore import ensure_claudeignore_entries
from dataairlock.vscode_compat.mapping_storage import MappingStorage
from dataairlock.vscode_compat.patterns import DEFAULT_PATTERNS
from dataairlock.vscode_compat.pii_detector import PIIDetector
from dataairlock.vscode_compat.types import PIIPattern, PIIType

vscode_app = typer.Typer(
    name="vscode",
    help="VSCode互換モード（airlock/.mapping + [TYPE_001]）",
    no_args_is_help=True,
)

console = Console()


def _build_detector(dob_mode: str) -> PIIDetector:
    patterns = []
    for p in DEFAULT_PATTERNS:
        if p.type == PIIType.DOB:
            if dob_mode == "off":
                continue
            if dob_mode == "anywhere":
                patterns.append(
                    PIIPattern(
                        type=p.type,
                        patterns=p.patterns,
                        enabled=True,
                        priority=p.priority,
                        context_required=p.context_required,
                    )
                )
                continue
        patterns.append(p)
    return PIIDetector(patterns)


def _parse_extensions(extensions: str | None) -> list[str]:
    if not extensions:
        return DEFAULT_EXTENSIONS
    exts = []
    for part in extensions.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.startswith("."):
            part = "." + part
        exts.append(part.lower())
    return exts or DEFAULT_EXTENSIONS


def _infer_mapping_path(
    target: Path,
    workspace_root: Path,
    airlock_folder_name: str,
) -> Path | None:
    airlock_base = workspace_root / airlock_folder_name
    try:
        rel = target.resolve().relative_to(airlock_base.resolve())
    except Exception:
        return None

    parts = rel.parts
    if not parts:
        return None
    source_name = parts[0]
    return MappingStorage.mapping_path(airlock_base, source_name)


@vscode_app.command("anonymize-folder")
def anonymize_folder(
    source_folder: Path = typer.Argument(..., help="仮名化する元フォルダ"),
    workspace_root: Path = typer.Option(Path("."), "--workspace-root", help="ワークスペースルート（airlock/ と .claudeignore を置く場所）"),
    airlock_folder_name: str = typer.Option("airlock", "--airlock-folder-name", help="出力ベースフォルダ名"),
    source_name: str | None = typer.Option(None, "--source-name", help="airlock/配下のフォルダ名（未指定なら元フォルダ名）"),
    extensions: str | None = typer.Option(None, "--extensions", help="対象拡張子（カンマ区切り、例: .txt,.md,.yaml）"),
    dob_mode: str = typer.Option("context", "--dob-mode", help="DOB検出: context/anywhere/off"),
    hide_original: bool = typer.Option(True, "--hide-original/--no-hide-original", help="元フォルダを .claudeignore に追加してClaudeから隠す"),
):
    workspace_root = workspace_root.resolve()
    source_folder = source_folder.resolve()

    if not source_folder.exists() or not source_folder.is_dir():
        raise typer.BadParameter(f"フォルダが見つかりません: {source_folder}")

    if dob_mode not in {"context", "anywhere", "off"}:
        raise typer.BadParameter("dob-mode は context/anywhere/off のいずれかです")

    detector = _build_detector(dob_mode)
    processor = FileProcessor(detector=detector, anonymizer=Anonymizer())

    result = processor.anonymize_folder(
        workspace_root=workspace_root,
        source_folder=source_folder,
        airlock_folder_name=airlock_folder_name,
        source_name=source_name,
        extensions=_parse_extensions(extensions),
        hide_original=hide_original,
    )

    # .claudeignore（必ず mapping を隠す）
    entries = [f"{airlock_folder_name}/.mapping/"]
    if hide_original:
        try:
            rel = source_folder.relative_to(workspace_root)
            entries.append(f"{rel.as_posix().rstrip('/')}/")
        except Exception:
            console.print("[yellow]警告: 元フォルダが workspace_root 配下にないため、.claudeignore に元フォルダを追加できません[/yellow]")

    ensure_claudeignore_entries(workspace_root, entries)

    mapping_str = str(result.mapping_path) if result.mapping_path else "(PII未検出のため未作成)"
    console.print(
        Panel(
            f"[bold]入力:[/bold] {source_folder}\n"
            f"[bold]出力:[/bold] {result.output_folder}\n"
            f"[bold]ファイル数:[/bold] {result.files_processed}\n"
            f"[bold]PII検出数:[/bold] {result.pii_found}\n"
            f"[bold]マッピング:[/bold] {mapping_str}",
            title="DataAirlock VSCode互換: anonymize-folder",
        )
    )
    if result.errors:
        console.print("[yellow]一部エラー:[/yellow]")
        for e in result.errors[:10]:
            console.print(f"  - {e}")
        if len(result.errors) > 10:
            console.print(f"  ... ({len(result.errors) - 10} more)")


@vscode_app.command("apply-mapping")
def apply_mapping(
    target: Path = typer.Argument(..., help="マッピングを適用するファイルまたはフォルダ"),
    mapping: Path | None = typer.Option(None, "-m", "--mapping", help="mapping JSON（未指定なら airlock から自動推定）"),
    workspace_root: Path = typer.Option(Path("."), "--workspace-root", help="ワークスペースルート（自動推定用）"),
    airlock_folder_name: str = typer.Option("airlock", "--airlock-folder-name", help="airlock ベースフォルダ名（自動推定用）"),
    extensions: str | None = typer.Option(None, "--extensions", help="対象拡張子（カンマ区切り）"),
    in_place: bool = typer.Option(True, "--in-place/--copy", help="in-place で書き換える（--copy で restored/ に複製）"),
    backup: bool = typer.Option(True, "--backup/--no-backup", help="in-place 時に .bak を作る"),
    yes: bool = typer.Option(False, "-y", "--yes", help="確認なし（in-place 時）"),
):
    workspace_root = workspace_root.resolve()
    target = target.resolve()

    if not target.exists():
        raise typer.BadParameter(f"対象が見つかりません: {target}")

    if mapping is None:
        inferred = _infer_mapping_path(target, workspace_root, airlock_folder_name)
        if inferred is None:
            raise typer.BadParameter("mapping を指定してください（自動推定に失敗しました）")
        mapping = inferred

    mapping = mapping.resolve()
    if not mapping.exists():
        raise typer.BadParameter(f"mapping が見つかりません: {mapping}")

    if in_place and not yes:
        if not typer.confirm(f"in-place で書き換えますか？（backup={'ON' if backup else 'OFF'}）"):
            raise typer.Exit(0)

    detector = _build_detector("context")
    processor = FileProcessor(detector=detector, anonymizer=Anonymizer())
    result = processor.apply_mapping(
        target_path=target,
        mapping_path=mapping,
        extensions=_parse_extensions(extensions),
        in_place=in_place,
        backup=backup,
    )

    console.print(
        Panel(
            f"[bold]対象:[/bold] {target}\n"
            f"[bold]mapping:[/bold] {mapping}\n"
            f"[bold]ファイル数:[/bold] {result.files_processed}\n"
            f"[bold]置換数:[/bold] {result.replaced_count}",
            title="DataAirlock VSCode互換: apply-mapping",
        )
    )
    if result.errors:
        console.print("[yellow]一部エラー:[/yellow]")
        for e in result.errors[:10]:
            console.print(f"  - {e}")
        if len(result.errors) > 10:
            console.print(f"  ... ({len(result.errors) - 10} more)")


@vscode_app.command("deanonymize-folder")
def deanonymize_folder(
    airlock_output_folder: Path = typer.Argument(..., help="airlock/<SOURCE_NAME> フォルダ"),
    mapping: Path | None = typer.Option(None, "-m", "--mapping", help="mapping JSON（未指定なら自動推定）"),
    workspace_root: Path = typer.Option(Path("."), "--workspace-root", help="ワークスペースルート（自動推定用）"),
    airlock_folder_name: str = typer.Option("airlock", "--airlock-folder-name", help="airlock ベースフォルダ名（自動推定用）"),
    extensions: str | None = typer.Option(None, "--extensions", help="対象拡張子（カンマ区切り）"),
    in_place: bool = typer.Option(True, "--in-place/--copy", help="in-place で書き換える（--copy で restored/ に複製）"),
    backup: bool = typer.Option(True, "--backup/--no-backup", help="in-place 時に .bak を作る"),
    yes: bool = typer.Option(False, "-y", "--yes", help="確認なし（in-place 時）"),
):
    # deanonymize-folder は apply-mapping のショートカット
    apply_mapping(
        target=airlock_output_folder,
        mapping=mapping,
        workspace_root=workspace_root,
        airlock_folder_name=airlock_folder_name,
        extensions=extensions,
        in_place=in_place,
        backup=backup,
        yes=yes,
    )
