"""DataAirlock CLI アプリケーション"""

import getpass
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.tree import Tree

from dataairlock.anonymizer import (
    Confidence,
    PIIColumnResult,
    PIIType,
    anonymize_dataframe,
    deanonymize_dataframe,
    detect_pii_columns,
    load_mapping,
    save_mapping,
)
from dataairlock.document_anonymizer import (
    DocumentAnonymizer,
    DocumentPIIResult,
    anonymize_document,
    deanonymize_document,
    scan_document,
)
from dataairlock.profile import ProfileManager
from dataairlock.hybrid_detector import (
    HybridPIIDetector,
    DetectionMode,
    detect_pii_hybrid,
)

app = typer.Typer(
    name="dataairlock",
    help="個人情報を匿名化してクラウドLLMに安全に渡すためのCLIツール",
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """DataAirlock - 機密データを安全にクラウドLLMへ"""
    if ctx.invoked_subcommand is None:
        from dataairlock.tui import run_tui
        run_tui()

console = Console()

# ワークスペース設定
AIRLOCK_DIR = ".airlock"
AIRLOCK_DATA_DIR = "data"
AIRLOCK_MAPPINGS_DIR = ".airlock_mappings"  # プロジェクトルートに配置
AIRLOCK_OUTPUT_DIR = "output"
AIRLOCK_CONFIG = "airlock.json"
SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".xls"}
DOCUMENT_EXTENSIONS = {".docx", ".pptx"}


def load_dataframe(file_path: Path) -> pd.DataFrame:
    """ファイルをDataFrameとして読み込む"""
    if file_path.suffix.lower() == ".csv":
        return pd.read_csv(file_path)
    elif file_path.suffix.lower() in [".xlsx", ".xls"]:
        return pd.read_excel(file_path)
    else:
        raise typer.BadParameter(f"サポートされていないファイル形式: {file_path.suffix}")


def save_dataframe(df: pd.DataFrame, file_path: Path) -> None:
    """DataFrameをUTF-8 BOM付きCSVとして保存"""
    with open(file_path, "wb") as f:
        f.write(b'\xef\xbb\xbf')
        f.write(df.to_csv(index=False).encode('utf-8'))


def get_confidence_symbol(confidence: Confidence) -> str:
    """確度に応じた記号を返す"""
    if confidence == Confidence.HIGH:
        return "[red]高[/red]"
    elif confidence == Confidence.MEDIUM:
        return "[yellow]中[/yellow]"
    else:
        return "[green]低[/green]"


def generate_prompt_file(
    original_filename: str,
    row_count: int,
    columns: list[str],
    anonymized_info: list[dict],
) -> str:
    """LLM用プロンプトを生成"""
    columns_str = ", ".join(columns)

    anonymized_lines = []
    for info in anonymized_info:
        action_desc = {
            "replaced": "replace（元データ復元可能）",
            "generalized": "generalize（一般化）",
            "deleted": "delete（削除済み）",
        }.get(info["action"], info["action"])
        anonymized_lines.append(f"- {info['column']}: {action_desc}")

    anonymized_section = "\n".join(anonymized_lines) if anonymized_lines else "- なし"

    return f"""このCSVは匿名化済みデータです。

## データ概要
- 元ファイル: {original_filename}
- 行数: {row_count}
- 列: {columns_str}

## 匿名化された列
{anonymized_section}

## 重要な指示
- 処理結果はCSV形式で出力してください
- ANON_で始まるIDはそのまま保持してください
- 新しい列を追加してもANON_ID列は削除しないでください

## 依頼内容
[ここに依頼を記述]
"""


def get_password_interactive(confirm: bool = True) -> str:
    """対話的にパスワードを取得"""
    while True:
        password = getpass.getpass("パスワードを入力: ")
        if not password:
            console.print("[red]パスワードを入力してください[/red]")
            continue

        if confirm:
            password_confirm = getpass.getpass("パスワード（確認）: ")
            if password != password_confirm:
                console.print("[red]パスワードが一致しません[/red]")
                continue

        if len(password) < 8:
            console.print("[yellow]警告: パスワードは8文字以上を推奨します[/yellow]")

        return password


@app.command()
def scan(
    input_file: Path = typer.Argument(..., help="入力ファイル（CSV/Excel）"),
    detection_mode: str = typer.Option(
        "rule",
        "-m", "--detection-mode",
        help="検出モード: rule/llm/hybrid",
    ),
):
    """
    PIIを検出して表示（匿名化は実行しない）

    検出モード:
    - rule: ルールベース（正規表現）のみ（デフォルト、高速）
    - llm: LLM（Ollama）のみ（精度重視）
    - hybrid: ルール + LLM の併用（推奨）
    """
    # ファイル読み込み
    if not input_file.exists():
        console.print(f"[red]エラー: ファイルが見つかりません: {input_file}[/red]")
        raise typer.Exit(1)

    try:
        df = load_dataframe(input_file)
    except Exception as e:
        console.print(f"[red]エラー: ファイルの読み込みに失敗しました: {e}[/red]")
        raise typer.Exit(1)

    # 検出モードを解釈
    mode_map = {
        "rule": DetectionMode.RULE_ONLY,
        "llm": DetectionMode.LLM_ONLY,
        "hybrid": DetectionMode.HYBRID,
    }
    mode = mode_map.get(detection_mode.lower(), DetectionMode.RULE_ONLY)

    # PII検出
    if mode == DetectionMode.RULE_ONLY:
        pii_columns = detect_pii_columns(df)
    else:
        pii_columns = detect_pii_hybrid(df, mode=mode)

    # 結果表示
    console.print()
    console.print(Panel(f"📁 ファイル: [bold]{input_file.name}[/bold]（{len(df):,}行）"))
    console.print()

    console.print("[bold]🔍 検出されたPII列:[/bold]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("状態", width=4)
    table.add_column("列名", style="cyan")
    table.add_column("確度", width=6)
    table.add_column("検出タイプ")
    table.add_column("サンプル値")

    all_columns = list(df.columns)
    for col in all_columns:
        if col in pii_columns:
            result = pii_columns[col]
            confidence = get_confidence_symbol(result.confidence)
            samples = ", ".join(result.sample_values[:3]) if result.sample_values else "-"
            table.add_row(
                "[yellow]⚠️[/yellow]",
                col,
                f"[{confidence}]",
                result.pii_type.value,
                samples[:40] + "..." if len(samples) > 40 else samples,
            )
        else:
            table.add_row(
                "[green]✓[/green]",
                col,
                "-",
                "（個人情報なし）",
                "-",
            )

    console.print(table)
    console.print()

    if pii_columns:
        console.print(f"[yellow]⚠️  {len(pii_columns)}件の個人情報列を検出しました[/yellow]")
    else:
        console.print("[green]✓ 個人情報列は検出されませんでした[/green]")


@app.command()
def anonymize(
    input_file: Path = typer.Argument(..., help="入力ファイル（CSV/Excel）"),
    output: Path = typer.Option(
        Path("./output"),
        "-o", "--output",
        help="出力ディレクトリ",
    ),
    password: Optional[str] = typer.Option(
        None,
        "-p", "--password",
        help="マッピング暗号化パスワード（未指定なら対話的に入力）",
    ),
    strategy: str = typer.Option(
        "replace",
        "-s", "--strategy",
        help="デフォルト戦略: replace/generalize/delete",
    ),
    auto: bool = typer.Option(
        False,
        "--auto",
        help="確認なしで自動実行",
    ),
    detection_mode: str = typer.Option(
        "rule",
        "-m", "--detection-mode",
        help="検出モード: rule/llm/hybrid",
    ),
):
    """
    ファイルを匿名化する

    検出モード:
    - rule: ルールベース（正規表現）のみ（デフォルト、高速）
    - llm: LLM（Ollama）のみ（精度重視）
    - hybrid: ルール + LLM の併用（推奨）
    """
    # ファイル読み込み
    if not input_file.exists():
        console.print(f"[red]エラー: ファイルが見つかりません: {input_file}[/red]")
        raise typer.Exit(1)

    try:
        df = load_dataframe(input_file)
    except Exception as e:
        console.print(f"[red]エラー: ファイルの読み込みに失敗しました: {e}[/red]")
        raise typer.Exit(1)

    console.print(Panel(f"📁 ファイル: [bold]{input_file.name}[/bold]（{len(df):,}行）"))

    # 検出モードを解釈
    mode_map = {
        "rule": DetectionMode.RULE_ONLY,
        "llm": DetectionMode.LLM_ONLY,
        "hybrid": DetectionMode.HYBRID,
    }
    mode = mode_map.get(detection_mode.lower(), DetectionMode.RULE_ONLY)

    # PII検出
    if mode == DetectionMode.RULE_ONLY:
        pii_columns = detect_pii_columns(df)
    else:
        pii_columns = detect_pii_hybrid(df, mode=mode)

    if not pii_columns:
        console.print("[green]✓ 個人情報列は検出されませんでした[/green]")
        raise typer.Exit(0)

    console.print(f"\n[yellow]⚠️  {len(pii_columns)}件の個人情報列を検出しました[/yellow]\n")

    # 戦略の検証
    if strategy not in ["replace", "generalize", "delete"]:
        console.print(f"[red]エラー: 無効な戦略: {strategy}[/red]")
        raise typer.Exit(1)

    # 各列の処理方法を決定
    column_actions: dict[str, str] = {}

    if auto:
        # 自動モード: すべてデフォルト戦略を適用
        for col in pii_columns:
            column_actions[col] = strategy
    else:
        # 対話モード: 各列の処理を確認
        for col_name, result in pii_columns.items():
            samples = ", ".join(result.sample_values[:2]) if result.sample_values else "N/A"
            console.print(f"  [cyan]{col_name}[/cyan] [{result.pii_type.value}] サンプル: {samples}")

            # 一般化が効果的な列にはデフォルトでgeneralize
            default = strategy
            if result.pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
                default = "generalize"

            action = Prompt.ask(
                "    処理方法",
                choices=["r", "g", "d", "s"],
                default={"replace": "r", "generalize": "g", "delete": "d"}.get(default, "r"),
            )

            action_map = {"r": "replace", "g": "generalize", "d": "delete", "s": "skip"}
            column_actions[col_name] = action_map[action]

    # スキップ以外の列がない場合
    columns_to_process = {k: v for k, v in column_actions.items() if v != "skip"}
    if not columns_to_process:
        console.print("[yellow]処理対象の列がありません[/yellow]")
        raise typer.Exit(0)

    # パスワード取得
    if password is None:
        console.print()
        password = get_password_interactive(confirm=True)

    # 出力ディレクトリ作成
    output.mkdir(parents=True, exist_ok=True)

    # 匿名化実行
    console.print("\n[bold]匿名化を実行中...[/bold]")

    anonymized_df = df.copy()
    full_mapping: dict = {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "original_file": input_file.name,
            "columns_processed": list(columns_to_process.keys()),
        }
    }

    anonymized_info = []
    for col_name, action in columns_to_process.items():
        if col_name not in pii_columns:
            continue

        result = pii_columns[col_name]
        single_col_pii = {col_name: result}

        anonymized_df, col_mapping = anonymize_dataframe(
            anonymized_df,
            single_col_pii,
            strategy=action,  # type: ignore
        )

        if col_name in col_mapping:
            full_mapping[col_name] = col_mapping[col_name]
            anonymized_info.append({
                "column": col_name,
                "action": col_mapping[col_name].get("action", action),
            })

    # ファイル出力
    csv_path = output / "anonymized.csv"
    mapping_path = output / "mapping.enc"
    prompt_path = output / "prompt.txt"

    save_dataframe(anonymized_df, csv_path)
    save_mapping(full_mapping, mapping_path, password)

    prompt_content = generate_prompt_file(
        original_filename=input_file.name,
        row_count=len(df),
        columns=list(anonymized_df.columns),
        anonymized_info=anonymized_info,
    )
    prompt_path.write_text(prompt_content, encoding="utf-8")

    # 完了メッセージ
    console.print()
    console.print(Panel(
        "[green]✅ 匿名化が完了しました[/green]\n\n"
        f"  📄 {csv_path}\n"
        f"  🔐 {mapping_path}\n"
        f"  📝 {prompt_path}",
        title="出力ファイル",
    ))


@app.command()
def restore(
    result_file: Path = typer.Argument(..., help="復元対象のCSVファイル"),
    mapping: Path = typer.Option(
        ...,
        "-m", "--mapping",
        help="マッピングファイル（必須）",
    ),
    password: Optional[str] = typer.Option(
        None,
        "-p", "--password",
        help="パスワード（未指定なら対話的に入力）",
    ),
    output: Path = typer.Option(
        Path("restored.csv"),
        "-o", "--output",
        help="出力ファイル名",
    ),
):
    """
    匿名化されたデータを復元する
    """
    # ファイル確認
    if not result_file.exists():
        console.print(f"[red]エラー: ファイルが見つかりません: {result_file}[/red]")
        raise typer.Exit(1)

    if not mapping.exists():
        console.print(f"[red]エラー: マッピングファイルが見つかりません: {mapping}[/red]")
        raise typer.Exit(1)

    # 結果ファイル読み込み
    try:
        df = pd.read_csv(result_file)
    except Exception as e:
        console.print(f"[red]エラー: ファイルの読み込みに失敗しました: {e}[/red]")
        raise typer.Exit(1)

    console.print(Panel(f"📁 ファイル: [bold]{result_file.name}[/bold]（{len(df):,}行）"))

    # パスワード取得
    if password is None:
        password = get_password_interactive(confirm=False)

    # マッピング読み込み
    try:
        mapping_data = load_mapping(mapping, password)
    except ValueError as e:
        console.print(f"[red]エラー: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]エラー: マッピングファイルの読み込みに失敗しました: {e}[/red]")
        raise typer.Exit(1)

    console.print("[green]✓ マッピングファイルを読み込みました[/green]")

    # マッピング情報表示
    metadata = mapping_data.get("metadata", {})
    console.print(f"  元ファイル: {metadata.get('original_file', '不明')}")
    console.print(f"  作成日時: {metadata.get('created_at', '不明')}")

    # 復元実行
    console.print("\n[bold]復元を実行中...[/bold]")
    restored_df = deanonymize_dataframe(df, mapping_data)

    # 保存
    save_dataframe(restored_df, output)

    # 復元統計
    console.print()
    table = Table(title="復元統計", show_header=True, header_style="bold")
    table.add_column("列名")
    table.add_column("元の処理")
    table.add_column("復元状態")

    for col_name, col_info in mapping_data.items():
        if col_name == "metadata":
            continue

        action = col_info.get("action", "unknown")
        values_mapping = col_info.get("values", {})

        if action == "deleted":
            table.add_row(col_name, "🗑️ 削除", "[red]❌ 復元不可[/red]")
        elif col_name in df.columns:
            reverse_mapping = {v: k for k, v in values_mapping.items()}
            restored_count = sum(1 for val in df[col_name] if str(val) in reverse_mapping)
            action_label = {"replaced": "🔄 置換", "generalized": "📊 一般化"}.get(action, action)
            table.add_row(col_name, action_label, f"[green]✅ {restored_count}件[/green]")
        else:
            action_label = {"replaced": "🔄 置換", "generalized": "📊 一般化"}.get(action, action)
            table.add_row(col_name, action_label, "[yellow]⚠️ 列なし[/yellow]")

    console.print(table)

    console.print()
    console.print(Panel(
        f"[green]✅ 復元が完了しました[/green]\n\n"
        f"  📄 {output}",
        title="出力ファイル",
    ))


@app.command()
def interactive():
    """
    対話モードで匿名化/復元を実行
    """
    console.print(Panel(
        "[bold cyan]DataAirlock[/bold cyan] - 対話モード\n"
        "個人情報を匿名化してクラウドLLMに安全に渡すためのツール",
        title="🔒",
    ))

    while True:
        console.print("\n[bold]何をしますか？[/bold]")
        console.print("  1. ファイルを匿名化")
        console.print("  2. 結果を復元")
        console.print("  3. PII検出のみ")
        console.print("  q. 終了")

        choice = Prompt.ask("選択", choices=["1", "2", "3", "q"], default="1")

        if choice == "q":
            console.print("[cyan]終了します[/cyan]")
            break

        if choice == "1":
            # 匿名化
            file_path = Prompt.ask("ファイルパスを入力")
            path = Path(file_path)

            if not path.exists():
                console.print(f"[red]エラー: ファイルが見つかりません: {path}[/red]")
                continue

            # anonymizeコマンドを呼び出し（対話モード）
            try:
                df = load_dataframe(path)
            except Exception as e:
                console.print(f"[red]エラー: {e}[/red]")
                continue

            pii_columns = detect_pii_columns(df)

            if not pii_columns:
                console.print("[green]✓ 個人情報列は検出されませんでした[/green]")
                continue

            console.print(f"\n[yellow]⚠️  {len(pii_columns)}件の個人情報列を検出しました[/yellow]\n")

            # 各列の処理方法
            column_actions: dict[str, str] = {}
            for col_name, result in pii_columns.items():
                samples = ", ".join(result.sample_values[:2]) if result.sample_values else "N/A"
                confidence = get_confidence_symbol(result.confidence)
                console.print(f"  [cyan]{col_name}[/cyan] [{confidence}] {result.pii_type.value}")
                console.print(f"    サンプル: {samples}")

                default = "r"
                if result.pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
                    default = "g"

                action = Prompt.ask(
                    "    処理方法 (r)eplace/(g)eneralize/(d)elete/(s)kip",
                    choices=["r", "g", "d", "s"],
                    default=default,
                )
                column_actions[col_name] = {"r": "replace", "g": "generalize", "d": "delete", "s": "skip"}[action]

            columns_to_process = {k: v for k, v in column_actions.items() if v != "skip"}
            if not columns_to_process:
                console.print("[yellow]処理対象の列がありません[/yellow]")
                continue

            # パスワード
            console.print()
            password = get_password_interactive(confirm=True)

            # 出力先
            output_dir = Path(Prompt.ask("出力ディレクトリ", default="./output"))
            output_dir.mkdir(parents=True, exist_ok=True)

            # 匿名化実行
            console.print("\n[bold]匿名化を実行中...[/bold]")

            anonymized_df = df.copy()
            full_mapping: dict = {
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "original_file": path.name,
                    "columns_processed": list(columns_to_process.keys()),
                }
            }

            anonymized_info = []
            for col_name, action in columns_to_process.items():
                if col_name not in pii_columns:
                    continue

                result = pii_columns[col_name]
                single_col_pii = {col_name: result}

                anonymized_df, col_mapping = anonymize_dataframe(
                    anonymized_df,
                    single_col_pii,
                    strategy=action,  # type: ignore
                )

                if col_name in col_mapping:
                    full_mapping[col_name] = col_mapping[col_name]
                    anonymized_info.append({
                        "column": col_name,
                        "action": col_mapping[col_name].get("action", action),
                    })

            # 保存
            csv_path = output_dir / "anonymized.csv"
            mapping_path = output_dir / "mapping.enc"
            prompt_path = output_dir / "prompt.txt"

            save_dataframe(anonymized_df, csv_path)
            save_mapping(full_mapping, mapping_path, password)

            prompt_content = generate_prompt_file(
                original_filename=path.name,
                row_count=len(df),
                columns=list(anonymized_df.columns),
                anonymized_info=anonymized_info,
            )
            prompt_path.write_text(prompt_content, encoding="utf-8")

            console.print()
            console.print(Panel(
                "[green]✅ 完了[/green]\n\n"
                f"  📄 {csv_path}\n"
                f"  🔐 {mapping_path}\n"
                f"  📝 {prompt_path}",
                title="出力ファイル",
            ))

        elif choice == "2":
            # 復元
            result_path = Path(Prompt.ask("結果ファイルのパス"))
            if not result_path.exists():
                console.print(f"[red]エラー: ファイルが見つかりません[/red]")
                continue

            mapping_path = Path(Prompt.ask("マッピングファイルのパス"))
            if not mapping_path.exists():
                console.print(f"[red]エラー: マッピングファイルが見つかりません[/red]")
                continue

            password = get_password_interactive(confirm=False)

            try:
                mapping_data = load_mapping(mapping_path, password)
            except ValueError as e:
                console.print(f"[red]エラー: {e}[/red]")
                continue

            console.print("[green]✓ マッピングファイルを読み込みました[/green]")

            df = pd.read_csv(result_path)
            restored_df = deanonymize_dataframe(df, mapping_data)

            output_path = Path(Prompt.ask("出力ファイル名", default="restored.csv"))
            save_dataframe(restored_df, output_path)

            console.print(Panel(
                f"[green]✅ 復元が完了しました[/green]\n\n"
                f"  📄 {output_path}",
                title="出力ファイル",
            ))

        elif choice == "3":
            # スキャン
            file_path = Prompt.ask("ファイルパスを入力")
            path = Path(file_path)

            if not path.exists():
                console.print(f"[red]エラー: ファイルが見つかりません[/red]")
                continue

            # scanコマンドを呼び出し
            scan(path)


# =============================================================================
# ドキュメント（Word/PowerPoint）コマンド
# =============================================================================

@app.command(name="scan-doc")
def scan_doc(
    input_file: Path = typer.Argument(..., help="入力ファイル（.docx/.pptx）"),
):
    """
    Word/PowerPointファイル内のPIIを検出して表示
    """
    if not input_file.exists():
        console.print(f"[red]エラー: ファイルが見つかりません: {input_file}[/red]")
        raise typer.Exit(1)

    suffix = input_file.suffix.lower()
    if suffix not in DOCUMENT_EXTENSIONS:
        console.print(f"[red]エラー: サポートされていないファイル形式: {suffix}[/red]")
        console.print("  対応形式: .docx, .pptx")
        raise typer.Exit(1)

    try:
        result = scan_document(input_file)
    except Exception as e:
        console.print(f"[red]エラー: ファイルの読み込みに失敗しました: {e}[/red]")
        raise typer.Exit(1)

    # 結果表示
    console.print()
    file_type = "Word" if suffix == ".docx" else "PowerPoint"
    console.print(Panel(f"📄 ファイル: [bold]{input_file.name}[/bold] ({file_type})"))
    console.print()

    console.print("[bold]🔍 検出されたPII:[/bold]")

    if result.total_matches == 0:
        console.print("[green]✓ 個人情報は検出されませんでした[/green]")
        raise typer.Exit(0)

    # PIIタイプ別統計
    table = Table(show_header=True, header_style="bold")
    table.add_column("PIIタイプ", style="cyan")
    table.add_column("検出数", justify="right")

    for pii_type, count in result.pii_by_type.items():
        table.add_row(pii_type, str(count))

    table.add_row("[bold]合計[/bold]", f"[bold]{result.total_matches}[/bold]")

    console.print(table)
    console.print()

    # サンプルマッチ
    if result.sample_matches:
        console.print("[bold]📝 サンプル（最大10件）:[/bold]")
        for i, match in enumerate(result.sample_matches[:10], 1):
            console.print(f"  {i}. [yellow]{match.original}[/yellow] ({match.pii_type.value})")

    console.print()
    console.print(f"[yellow]⚠️  {result.total_matches}件の個人情報を検出しました[/yellow]")


@app.command(name="anonymize-doc")
def anonymize_doc(
    input_file: Path = typer.Argument(..., help="入力ファイル（.docx/.pptx）"),
    output: Optional[Path] = typer.Option(
        None,
        "-o", "--output",
        help="出力ファイル（未指定なら自動生成）",
    ),
    password: Optional[str] = typer.Option(
        None,
        "-p", "--password",
        help="マッピング暗号化パスワード（未指定なら対話的に入力）",
    ),
    strategy: str = typer.Option(
        "replace",
        "-s", "--strategy",
        help="匿名化戦略: replace/generalize",
    ),
):
    """
    Word/PowerPointファイルを匿名化する
    """
    if not input_file.exists():
        console.print(f"[red]エラー: ファイルが見つかりません: {input_file}[/red]")
        raise typer.Exit(1)

    suffix = input_file.suffix.lower()
    if suffix not in DOCUMENT_EXTENSIONS:
        console.print(f"[red]エラー: サポートされていないファイル形式: {suffix}[/red]")
        console.print("  対応形式: .docx, .pptx")
        raise typer.Exit(1)

    # 戦略の検証
    if strategy not in ["replace", "generalize"]:
        console.print(f"[red]エラー: 無効な戦略: {strategy}[/red]")
        console.print("  ドキュメント匿名化では replace または generalize を使用してください")
        raise typer.Exit(1)

    # 出力パス決定
    if output is None:
        output_dir = Path("./output")
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"anonymized_{input_file.name}"
    else:
        # 出力先の親ディレクトリを作成
        output.parent.mkdir(parents=True, exist_ok=True)

    file_type = "Word" if suffix == ".docx" else "PowerPoint"
    console.print(Panel(f"📄 ファイル: [bold]{input_file.name}[/bold] ({file_type})"))

    # まずスキャン
    try:
        scan_result = scan_document(input_file)
    except Exception as e:
        console.print(f"[red]エラー: ファイルの読み込みに失敗しました: {e}[/red]")
        raise typer.Exit(1)

    if scan_result.total_matches == 0:
        console.print("[green]✓ 個人情報は検出されませんでした[/green]")
        raise typer.Exit(0)

    console.print(f"\n[yellow]⚠️  {scan_result.total_matches}件の個人情報を検出しました[/yellow]\n")

    # PIIタイプ別統計を表示
    console.print("[bold]検出されたPII:[/bold]")
    for pii_type, count in scan_result.pii_by_type.items():
        console.print(f"  - {pii_type}: {count}件")

    console.print()

    # パスワード取得
    if password is None:
        password = get_password_interactive(confirm=True)

    # 匿名化実行
    console.print("\n[bold]匿名化を実行中...[/bold]")

    try:
        result, mapping = anonymize_document(input_file, output, strategy)  # type: ignore
    except Exception as e:
        console.print(f"[red]エラー: 匿名化に失敗しました: {e}[/red]")
        raise typer.Exit(1)

    # マッピング保存
    mapping_path = output.parent / f"{output.stem}.mapping.enc"
    save_mapping(mapping, mapping_path, password)

    # 完了メッセージ
    console.print()
    console.print(Panel(
        f"[green]✅ 匿名化が完了しました[/green]\n\n"
        f"  📄 {output}\n"
        f"  🔐 {mapping_path}\n\n"
        f"  置換数: {result.total_matches}件",
        title="出力ファイル",
    ))


@app.command(name="restore-doc")
def restore_doc(
    input_file: Path = typer.Argument(..., help="復元対象のファイル（.docx/.pptx）"),
    mapping: Path = typer.Option(
        ...,
        "-m", "--mapping",
        help="マッピングファイル（必須）",
    ),
    password: Optional[str] = typer.Option(
        None,
        "-p", "--password",
        help="パスワード（未指定なら対話的に入力）",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o", "--output",
        help="出力ファイル名（未指定なら自動生成）",
    ),
):
    """
    匿名化されたWord/PowerPointファイルを復元する
    """
    if not input_file.exists():
        console.print(f"[red]エラー: ファイルが見つかりません: {input_file}[/red]")
        raise typer.Exit(1)

    if not mapping.exists():
        console.print(f"[red]エラー: マッピングファイルが見つかりません: {mapping}[/red]")
        raise typer.Exit(1)

    suffix = input_file.suffix.lower()
    if suffix not in DOCUMENT_EXTENSIONS:
        console.print(f"[red]エラー: サポートされていないファイル形式: {suffix}[/red]")
        console.print("  対応形式: .docx, .pptx")
        raise typer.Exit(1)

    # 出力パス決定
    if output is None:
        output = Path(f"restored_{input_file.name}")

    file_type = "Word" if suffix == ".docx" else "PowerPoint"
    console.print(Panel(f"📄 ファイル: [bold]{input_file.name}[/bold] ({file_type})"))

    # パスワード取得
    if password is None:
        password = get_password_interactive(confirm=False)

    # マッピング読み込み
    try:
        mapping_data = load_mapping(mapping, password)
    except ValueError as e:
        console.print(f"[red]エラー: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]エラー: マッピングファイルの読み込みに失敗しました: {e}[/red]")
        raise typer.Exit(1)

    console.print("[green]✓ マッピングファイルを読み込みました[/green]")

    # マッピング情報表示
    metadata = mapping_data.get("metadata", {})
    console.print(f"  元ファイル: {metadata.get('original_file', '不明')}")
    console.print(f"  作成日時: {metadata.get('created_at', '不明')}")
    console.print(f"  置換数: {metadata.get('total_replacements', '不明')}件")

    # 復元実行
    console.print("\n[bold]復元を実行中...[/bold]")

    try:
        deanonymize_document(input_file, output, mapping_data)
    except Exception as e:
        console.print(f"[red]エラー: 復元に失敗しました: {e}[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(Panel(
        f"[green]✅ 復元が完了しました[/green]\n\n"
        f"  📄 {output}",
        title="出力ファイル",
    ))


# =============================================================================
# Workspace コマンド
# =============================================================================

def _get_airlock_path(directory: Path) -> Path:
    """airlockディレクトリのパスを取得"""
    return directory / AIRLOCK_DIR


def _get_config_path(directory: Path) -> Path:
    """設定ファイルのパスを取得"""
    return _get_airlock_path(directory) / AIRLOCK_CONFIG


def _load_workspace_config(directory: Path) -> dict | None:
    """ワークスペース設定を読み込み"""
    config_path = _get_config_path(directory)
    if not config_path.exists():
        return None
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_workspace_config(directory: Path, config: dict) -> None:
    """ワークスペース設定を保存"""
    config_path = _get_config_path(directory)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def _generate_airlock_gitignore() -> str:
    """airlock用.gitignoreを生成"""
    return """# DataAirlock - ローカル設定
airlock.json
"""


def _generate_mappings_gitignore() -> str:
    """マッピングディレクトリ用.gitignoreを生成（全ファイル除外）"""
    return "*\n"


def _generate_airlock_readme(airlock_path: Path, files_info: list[dict] | None = None) -> str:
    """airlock用README.mdを生成（汎用・全ツール向け）"""
    files_section = ""
    if files_info:
        files_list = "\n".join([f"  - `data/{info['name']}` ← {info['original']}" for info in files_info])
        files_section = f"""
## 利用可能なデータ

{files_list}
"""

    return f"""# DataAirlock Workspace

このディレクトリはDataAirlockによって生成された**セキュアな作業環境**です。
個人情報は匿名化されており、安全にAIツールで分析できます。

## ディレクトリ構造

```
.airlock/
├── data/           # 匿名化済みデータ（AIに渡してOK）
├── output/         # 分析結果の出力先
├── CLAUDE.md       # Claude Code用設定
├── SYSTEM_PROMPT.md # 汎用システムプロンプト
└── README.md       # このファイル
```
{files_section}
## 匿名化IDについて

データ内の以下の形式は匿名化された個人情報です：

| 形式 | 意味 | 例 |
|------|------|-----|
| `PERSON_001_XXXX` | 人名 | 山田太郎 → PERSON_001_A7K2 |
| `PATIENT_001_XXXX` | 患者ID | P001 → PATIENT_001_A7K2 |
| `PHONE_001_XXXX` | 電話番号 | 03-1234-5678 → PHONE_001_A7K2 |
| `EMAIL_001_XXXX` | メール | test@example.com → EMAIL_001_A7K2 |
| `ADDR_001_XXXX` | 住所 | 東京都新宿区... → ADDR_001_A7K2 |

※ 末尾の4文字（例: A7K2）はセッションIDで、同一ファイル内で共通です。

## ワークフロー

1. **分析**: `data/` 内のファイルをAIツールで分析
2. **出力**: 結果を `output/` に保存（匿名化IDはそのまま維持）
3. **復元**: プロジェクトルートで `dataairlock workspace ../ --restore-all` を実行

## 注意事項

- 復元用マッピングは `../{AIRLOCK_MAPPINGS_DIR}/` に保存されています（Git除外済み）
- このディレクトリ外のファイルにはアクセスしないでください
"""


def _generate_claude_md(files_info: list[dict] | None = None) -> str:
    """CLAUDE.md を生成（Claude Code用）"""
    files_section = ""
    if files_info:
        files_list = "\n".join([f"- `data/{info['name']}`" for info in files_info])
        files_section = f"""
## 利用可能なファイル

{files_list}
"""

    return f"""# DataAirlock セキュア環境

このワークスペースには**匿名化された機密データ**が含まれています。
以下のルールを厳守してください。

## 絶対ルール

### 禁止事項
- **このディレクトリ外のファイルを読み込まない**（`../` へのアクセス禁止）
- **匿名化IDから元の値を推測・復元しようとしない**
- **匿名化IDを変更・削除しない**
- **データを外部に送信しない**

### 必須事項
- 結果ファイルは必ず `output/` ディレクトリに保存する
- 匿名化ID（`PERSON_001_XXXX` 形式）はそのまま維持する
- 新しい列を追加する場合も、既存の匿名化ID列は保持する
{files_section}
## 匿名化IDの形式

| プレフィックス | 意味 |
|--------------|------|
| `PERSON_` | 人名 |
| `PATIENT_` | 患者ID |
| `PHONE_` | 電話番号 |
| `EMAIL_` | メールアドレス |
| `ADDR_` | 住所 |
| `BIRTHDATE_` | 生年月日 |
| `AGE_` | 年齢 |
| `MYNUMBER_` | マイナンバー |

## 出力形式

分析結果をCSVで出力する場合：
```python
df.to_csv("output/result.csv", index=False, encoding="utf-8-sig")
```

## 復元について

匿名化IDの復元はこのワークスペース外で行われます。
あなたは復元処理を行う必要はありません。
"""


def _generate_system_prompt_md(files_info: list[dict] | None = None) -> str:
    """SYSTEM_PROMPT.md を生成（Aider等の汎用LLMツール用）"""
    files_section = ""
    if files_info:
        files_list = "\n".join([f"- data/{info['name']}" for info in files_info])
        files_section = f"""
利用可能なファイル:
{files_list}
"""

    return f"""あなたはDataAirlockセキュア環境内で作業するAIアシスタントです。

# 環境説明

このディレクトリには匿名化された機密データが含まれています。
個人情報は `PERSON_001_A7K2` のような形式で匿名化されています。

# 厳守ルール

1. このディレクトリ外のファイルを絶対に読み込まないでください
2. 匿名化IDから元の値を推測しようとしないでください
3. 結果は必ず output/ ディレクトリに保存してください
4. 匿名化ID列は削除・変更せず、そのまま維持してください

# 禁止コマンド例

- `cat ../` や `ls ../` など親ディレクトリへのアクセス
- `find /` など広範囲の検索
- 外部へのデータ送信
{files_section}
# 作業手順

1. data/ 内のファイルを読み込む
2. 分析・処理を行う
3. 結果を output/ に保存する

匿名化IDの復元は別途行われるため、あなたが行う必要はありません。
"""


def _generate_prompt_md(files_info: list[dict]) -> str:
    """PROMPT.mdを生成（分析依頼テンプレート）"""
    files_table = "| ファイル | 元ファイル | 匿名化列 |\n|---------|-----------|----------|\n"
    for info in files_info:
        pii_cols = ", ".join(info.get("pii_columns", [])) or "なし"
        files_table += f"| data/{info['name']} | {info['original']} | {pii_cols} |\n"

    return f"""# 分析依頼

## 対象データ

{files_table}

## 依頼内容

[ここに具体的な分析依頼を記述してください]

例:
- 基本統計量を算出してください
- 年代別の傾向を分析してください
- 異常値を検出してください

## 出力形式

- 結果ファイル: `output/` ディレクトリに保存
- 形式: CSV（UTF-8 BOM付き推奨）

## 注意

- 匿名化ID（`PERSON_001_XXXX` 形式）はそのまま維持してください
- このディレクトリ外のファイルにはアクセスしないでください
"""


def _get_mappings_path(directory: Path) -> Path:
    """マッピングディレクトリのパスを取得（プロジェクトルート）"""
    return directory / AIRLOCK_MAPPINGS_DIR


def _init_workspace(directory: Path) -> Path:
    """ワークスペースを初期化"""
    airlock_path = _get_airlock_path(directory)
    data_path = airlock_path / AIRLOCK_DATA_DIR
    mappings_path = _get_mappings_path(directory)  # プロジェクトルートに配置
    output_path = airlock_path / AIRLOCK_OUTPUT_DIR

    # ディレクトリ作成
    data_path.mkdir(parents=True, exist_ok=True)
    mappings_path.mkdir(parents=True, exist_ok=True)
    output_path.mkdir(parents=True, exist_ok=True)

    # .airlock/.gitignore作成
    gitignore_path = airlock_path / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text(_generate_airlock_gitignore(), encoding="utf-8")

    # .airlock_mappings/.gitignore作成（全ファイル除外）
    mappings_gitignore_path = mappings_path / ".gitignore"
    if not mappings_gitignore_path.exists():
        mappings_gitignore_path.write_text(_generate_mappings_gitignore(), encoding="utf-8")

    return airlock_path


@app.command()
def workspace(
    project_dir: Path = typer.Argument(..., help="プロジェクトディレクトリ"),
    add: Optional[Path] = typer.Option(
        None,
        "--add", "-a",
        help="匿名化して追加するファイル",
    ),
    add_all: Optional[Path] = typer.Option(
        None,
        "--add-all",
        help="フォルダ内の全CSV/Excelファイルを一括追加",
    ),
    status: bool = typer.Option(
        False,
        "--status", "-s",
        help="ワークスペースの状態を表示",
    ),
    restore: Optional[Path] = typer.Option(
        None,
        "--restore", "-r",
        help="出力ファイルを復元",
    ),
    restore_all: bool = typer.Option(
        False,
        "--restore-all",
        help="output/内の全CSVを一括復元",
    ),
    clean: bool = typer.Option(
        False,
        "--clean",
        help="ワークスペースを削除",
    ),
    password: Optional[str] = typer.Option(
        None,
        "-p", "--password",
        help="パスワード",
    ),
):
    """
    セキュアなワークスペースを管理

    \b
    使用例:
      # ワークスペース初期化 + ファイル追加
      dataairlock workspace ./my_project --add data/患者データ.csv

      # フォルダ内の全ファイルを一括追加
      dataairlock workspace ./my_project --add-all ./raw_data

      # 既存ワークスペースにファイル追加
      dataairlock workspace ./my_project --add another_file.csv

      # ワークスペースの状態確認
      dataairlock workspace ./my_project --status

      # Claude Codeの出力を復元
      dataairlock workspace ./my_project --restore output/result.csv

      # output/内の全CSVを一括復元
      dataairlock workspace ./my_project --restore-all

      # ワークスペースをクリーンアップ
      dataairlock workspace ./my_project --clean
    """
    project_dir = project_dir.resolve()

    if not project_dir.exists():
        console.print(f"[red]エラー: ディレクトリが見つかりません: {project_dir}[/red]")
        raise typer.Exit(1)

    airlock_path = _get_airlock_path(project_dir)

    # --clean オプション
    if clean:
        mappings_path = _get_mappings_path(project_dir)

        if not airlock_path.exists() and not mappings_path.exists():
            console.print(f"[yellow]ワークスペースが見つかりません: {airlock_path}[/yellow]")
            raise typer.Exit(0)

        console.print(f"[yellow]警告: 以下を削除します[/yellow]")
        if airlock_path.exists():
            console.print(f"  - {airlock_path}")
        if mappings_path.exists():
            console.print(f"  - {mappings_path}")

        if not Confirm.ask("本当に削除しますか？"):
            console.print("キャンセルしました")
            raise typer.Exit(0)

        if airlock_path.exists():
            shutil.rmtree(airlock_path)
        if mappings_path.exists():
            shutil.rmtree(mappings_path)
        console.print(f"[green]✓ ワークスペースを削除しました[/green]")
        raise typer.Exit(0)

    # --status オプション
    if status:
        if not airlock_path.exists():
            console.print(f"[yellow]ワークスペースが見つかりません: {airlock_path}[/yellow]")
            console.print("  'dataairlock workspace <dir> --add <file>' で作成してください")
            raise typer.Exit(0)

        config = _load_workspace_config(project_dir)
        if not config:
            console.print("[red]エラー: ワークスペース設定が見つかりません[/red]")
            raise typer.Exit(1)

        # 情報表示
        console.print(Panel(
            f"[bold cyan]DataAirlock Workspace[/bold cyan]\n\n"
            f"📁 プロジェクト: {project_dir}\n"
            f"📁 ワークスペース: {airlock_path}\n"
            f"📅 作成日時: {config.get('created_at', '不明')}",
            title="🔒 ワークスペース情報",
        ))

        # ファイル一覧
        tree = Tree(f"📂 [cyan]{AIRLOCK_DIR}/[/cyan]")
        data_branch = tree.add(f"📁 {AIRLOCK_DATA_DIR}/")
        mapping_branch = tree.add(f"📁 ../{AIRLOCK_MAPPINGS_DIR}/ [dim](Git除外)[/dim]")
        output_branch = tree.add(f"📁 {AIRLOCK_OUTPUT_DIR}/")

        for file_name, file_info in config.get("files", {}).items():
            pii_cols = file_info.get("pii_columns", [])
            if pii_cols:
                pii_str = f" [yellow]({', '.join(pii_cols)})[/yellow]"
                data_branch.add(f"[yellow]{file_name}[/yellow]{pii_str}")
                mapping_branch.add(f"[dim]{file_name}.mapping.enc[/dim]")
            else:
                data_branch.add(f"[green]{file_name}[/green]")

        # output内のファイル
        output_dir = airlock_path / AIRLOCK_OUTPUT_DIR
        if output_dir.exists():
            for f in output_dir.iterdir():
                if f.is_file():
                    output_branch.add(f"[cyan]{f.name}[/cyan]")

        console.print()
        console.print(tree)

        console.print()
        console.print("[bold]使い方:[/bold]")
        console.print(f"  🚀 Claude Code を起動: [cyan]cd {airlock_path} && claude[/cyan]")
        console.print(f"  📥 結果を復元: [cyan]dataairlock workspace {project_dir} --restore output/result.csv[/cyan]")
        raise typer.Exit(0)

    # --restore オプション
    if restore:
        if not airlock_path.exists():
            console.print(f"[red]エラー: ワークスペースが見つかりません: {airlock_path}[/red]")
            raise typer.Exit(1)

        config = _load_workspace_config(project_dir)
        if not config:
            console.print("[red]エラー: ワークスペース設定が見つかりません[/red]")
            raise typer.Exit(1)

        # 復元対象ファイル
        restore_path = airlock_path / restore
        if not restore_path.exists():
            # output/以下を探す
            restore_path = airlock_path / AIRLOCK_OUTPUT_DIR / restore
            if not restore_path.exists():
                console.print(f"[red]エラー: ファイルが見つかりません: {restore}[/red]")
                raise typer.Exit(1)

        console.print(Panel(
            f"[bold cyan]DataAirlock Restore[/bold cyan]\n\n"
            f"📄 復元対象: {restore_path.relative_to(airlock_path)}",
            title="🔓 結果復元",
        ))

        # パスワード取得
        if password is None:
            password = get_password_interactive(confirm=False)

        # 復元に使用するマッピングを収集
        all_mappings: dict = {}
        mapping_dir = _get_mappings_path(project_dir)

        for mapping_file in mapping_dir.glob("*.mapping.enc"):
            try:
                mapping_data = load_mapping(mapping_file, password)
                # 全マッピングをマージ
                for col_name, col_info in mapping_data.items():
                    if col_name != "metadata" and "values" in col_info:
                        if col_name not in all_mappings:
                            all_mappings[col_name] = col_info
            except Exception as e:
                console.print(f"[yellow]警告: {mapping_file.name} の読み込みに失敗: {e}[/yellow]")

        if not all_mappings:
            console.print("[yellow]警告: 有効なマッピングが見つかりません[/yellow]")

        # 復元実行
        try:
            df = pd.read_csv(restore_path)
            restored_df = deanonymize_dataframe(df, all_mappings)

            # 出力先
            results_dir = project_dir / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            output_path = results_dir / restore_path.name

            save_dataframe(restored_df, output_path)

            console.print()
            console.print(Panel(
                f"[green]✅ 復元が完了しました[/green]\n\n"
                f"📄 出力: [cyan]{output_path}[/cyan]",
                title="🔓 完了",
            ))
        except Exception as e:
            console.print(f"[red]エラー: 復元に失敗しました: {e}[/red]")
            raise typer.Exit(1)

        raise typer.Exit(0)

    # --restore-all オプション
    if restore_all:
        if not airlock_path.exists():
            console.print(f"[red]エラー: ワークスペースが見つかりません: {airlock_path}[/red]")
            raise typer.Exit(1)

        config = _load_workspace_config(project_dir)
        if not config:
            console.print("[red]エラー: ワークスペース設定が見つかりません[/red]")
            raise typer.Exit(1)

        output_dir = airlock_path / AIRLOCK_OUTPUT_DIR
        if not output_dir.exists():
            console.print(f"[red]エラー: output/ ディレクトリが見つかりません[/red]")
            raise typer.Exit(1)

        # CSVファイルを再帰的に列挙
        csv_files = list(output_dir.glob("**/*.csv"))
        if not csv_files:
            console.print(f"[yellow]output/ 内にCSVファイルがありません[/yellow]")
            raise typer.Exit(0)

        console.print(Panel(
            f"[bold cyan]DataAirlock Restore All[/bold cyan]\n\n"
            f"📁 output/ 以下のファイル: {len(csv_files)}件",
            title="🔓 一括復元",
        ))

        console.print("\n[bold]📄 対象ファイル:[/bold]")
        for f in csv_files:
            # output_dir からの相対パスを表示
            rel_path = f.relative_to(output_dir)
            console.print(f"  - {rel_path}")

        # パスワード取得
        if password is None:
            console.print()
            password = get_password_interactive(confirm=False)

        # マッピングを収集
        all_mappings: dict = {}
        mapping_dir = _get_mappings_path(project_dir)

        for mapping_file in mapping_dir.glob("*.mapping.enc"):
            try:
                mapping_data = load_mapping(mapping_file, password)
                for col_name, col_info in mapping_data.items():
                    if col_name != "metadata" and "values" in col_info:
                        if col_name not in all_mappings:
                            all_mappings[col_name] = col_info
            except Exception as e:
                console.print(f"[yellow]警告: {mapping_file.name} の読み込みに失敗: {e}[/yellow]")

        if not all_mappings:
            console.print("[yellow]警告: 有効なマッピングが見つかりません[/yellow]")

        # 復元実行
        results_dir = project_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        restored_count = 0

        console.print("\n[bold]復元を実行中...[/bold]")

        for csv_file in csv_files:
            try:
                # output_dir からの相対パスを維持
                rel_path = csv_file.relative_to(output_dir)
                output_path = results_dir / rel_path

                # 親ディレクトリを作成
                output_path.parent.mkdir(parents=True, exist_ok=True)

                df = pd.read_csv(csv_file)
                restored_df = deanonymize_dataframe(df, all_mappings)
                save_dataframe(restored_df, output_path)
                console.print(f"  [green]✓[/green] {rel_path}")
                restored_count += 1
            except Exception as e:
                rel_path = csv_file.relative_to(output_dir)
                console.print(f"  [red]✗[/red] {rel_path}: {e}")

        console.print()
        console.print(Panel(
            f"[green]✅ {restored_count}ファイルを復元しました[/green]\n\n"
            f"📂 results/",
            title="🔓 完了",
        ))
        raise typer.Exit(0)

    # --add-all オプション
    if add_all:
        folder_path = project_dir / add_all if not add_all.is_absolute() else add_all
        if not folder_path.exists():
            console.print(f"[red]エラー: フォルダが見つかりません: {folder_path}[/red]")
            raise typer.Exit(1)

        if not folder_path.is_dir():
            console.print(f"[red]エラー: ディレクトリではありません: {folder_path}[/red]")
            raise typer.Exit(1)

        # CSV/Excelファイルを列挙
        data_files: list[Path] = []
        for ext in SUPPORTED_EXTENSIONS:
            data_files.extend(folder_path.glob(f"*{ext}"))

        if not data_files:
            console.print(f"[yellow]フォルダ内にCSV/Excelファイルがありません[/yellow]")
            raise typer.Exit(0)

        console.print(Panel(
            f"[bold cyan]DataAirlock Workspace[/bold cyan]\n\n"
            f"📁 フォルダ: {folder_path}\n"
            f"📄 ファイル数: {len(data_files)}件",
            title="🔒 一括追加",
        ))

        # 各ファイルを読み込んでPII検出
        file_data: list[tuple[Path, pd.DataFrame, dict]] = []
        all_pii_columns: dict[str, PIIColumnResult] = {}

        console.print("\n[bold]📁 対象ファイル:[/bold]")
        for f in data_files:
            try:
                df = load_dataframe(f)
                pii_cols = detect_pii_columns(df)
                file_data.append((f, df, pii_cols))

                # 全ファイルのPII列を集約
                for col_name, result in pii_cols.items():
                    if col_name not in all_pii_columns:
                        all_pii_columns[col_name] = result

                pii_info = f" [yellow]({len(pii_cols)}列)[/yellow]" if pii_cols else ""
                console.print(f"  - {f.name} ({len(df):,}行){pii_info}")
            except Exception as e:
                console.print(f"  - [red]{f.name}: 読み込み失敗 ({e})[/red]")

        if not file_data:
            console.print("[red]エラー: 読み込めるファイルがありませんでした[/red]")
            raise typer.Exit(1)

        if not all_pii_columns:
            console.print("\n[green]✓ 個人情報は検出されませんでした[/green]")
            console.print("  データはそのまま安全に使用できます")
            raise typer.Exit(0)

        # 統合されたPII列の処理方法を決定
        console.print("\n[bold]🔍 検出されたPII列（全ファイル共通）:[/bold]")
        column_actions: dict[str, str] = {}

        for col_name, result in all_pii_columns.items():
            samples = ", ".join(result.sample_values[:2]) if result.sample_values else "N/A"
            confidence = get_confidence_symbol(result.confidence)

            console.print(f"  [yellow]⚠️[/yellow]  [cyan]{col_name}[/cyan] [{confidence}] {result.pii_type.value}")
            console.print(f"      サンプル: {samples}")

            # デフォルト設定
            default = "r"
            if result.pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
                default = "g"

            action = Prompt.ask(
                "      → (r)eplace/(g)eneralize/(d)elete/(s)kip",
                choices=["r", "g", "d", "s"],
                default=default,
            )
            column_actions[col_name] = {"r": "replace", "g": "generalize", "d": "delete", "s": "skip"}[action]

        # スキップ以外の列がない場合
        columns_to_process = {k: v for k, v in column_actions.items() if v != "skip"}
        if not columns_to_process:
            console.print("[yellow]処理対象の列がありません[/yellow]")
            raise typer.Exit(0)

        # パスワード取得
        config = _load_workspace_config(project_dir)
        is_new_workspace = config is None

        if password is None:
            console.print()
            password = get_password_interactive(confirm=is_new_workspace)

        # ワークスペース初期化
        airlock_path = _init_workspace(project_dir)

        if config is None:
            config = {
                "created_at": datetime.now().isoformat(),
                "source_directory": str(project_dir),
                "files": {},
            }

        # 全ファイルを匿名化
        console.print("\n[bold]匿名化を実行中...[/bold]")
        processed_count = 0

        for file_path, df, file_pii_cols in file_data:
            file_stem = file_path.stem

            # このファイルに関連するPII列のみ処理
            file_columns_to_process = {
                k: v for k, v in columns_to_process.items()
                if k in file_pii_cols
            }

            if not file_columns_to_process and not file_pii_cols:
                # PII列がないファイルはそのままコピー
                data_output = airlock_path / AIRLOCK_DATA_DIR / f"{file_stem}.csv"
                save_dataframe(df, data_output)
                config["files"][file_stem] = {
                    "name": f"{file_stem}.csv",
                    "original": str(file_path.relative_to(project_dir) if file_path.is_relative_to(project_dir) else file_path),
                    "pii_columns": [],
                }
                console.print(f"  [green]✓[/green] {file_path.name} (PII無し)")
                processed_count += 1
                continue

            # 匿名化実行
            anonymized_df = df.copy()
            full_mapping: dict = {
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "original_file": str(file_path.relative_to(project_dir) if file_path.is_relative_to(project_dir) else file_path),
                    "columns_processed": list(file_columns_to_process.keys()),
                }
            }

            for col_name, action in file_columns_to_process.items():
                if col_name not in file_pii_cols:
                    continue

                result = file_pii_cols[col_name]
                single_col_pii = {col_name: result}

                anonymized_df, col_mapping = anonymize_dataframe(
                    anonymized_df,
                    single_col_pii,
                    strategy=action,  # type: ignore
                )

                if col_name in col_mapping:
                    full_mapping[col_name] = col_mapping[col_name]

            # ファイル保存
            data_output = airlock_path / AIRLOCK_DATA_DIR / f"{file_stem}.csv"
            mapping_output = _get_mappings_path(project_dir) / f"{file_stem}.mapping.enc"

            save_dataframe(anonymized_df, data_output)
            save_mapping(full_mapping, mapping_output, password)

            # 設定更新
            config["files"][file_stem] = {
                "name": f"{file_stem}.csv",
                "original": str(file_path.relative_to(project_dir) if file_path.is_relative_to(project_dir) else file_path),
                "pii_columns": list(file_columns_to_process.keys()),
            }
            console.print(f"  [green]✓[/green] {file_path.name}")
            processed_count += 1

        _save_workspace_config(project_dir, config)

        # ドキュメント生成用のファイル情報
        files_info = [
            {
                "name": info["name"],
                "original": info["original"],
                "pii_columns": info.get("pii_columns", []),
            }
            for info in config["files"].values()
        ]

        # README.md生成（汎用）
        readme_path = airlock_path / "README.md"
        readme_path.write_text(_generate_airlock_readme(airlock_path, files_info), encoding="utf-8")

        # CLAUDE.md生成（Claude Code用）
        claude_md_path = airlock_path / "CLAUDE.md"
        claude_md_path.write_text(_generate_claude_md(files_info), encoding="utf-8")

        # SYSTEM_PROMPT.md生成（汎用LLMツール用）
        system_prompt_path = airlock_path / "SYSTEM_PROMPT.md"
        system_prompt_path.write_text(_generate_system_prompt_md(files_info), encoding="utf-8")

        # PROMPT.md生成（分析依頼テンプレート）
        prompt_path = airlock_path / "PROMPT.md"
        prompt_path.write_text(_generate_prompt_md(files_info), encoding="utf-8")

        # 完了メッセージ
        console.print()
        file_list = "\n".join([f"   ├── {info['name']}" for info in list(config["files"].values())[:-1]])
        if config["files"]:
            last_file = list(config["files"].values())[-1]["name"]
            file_list += f"\n   └── {last_file}" if file_list else f"   └── {last_file}"

        console.print(Panel(
            f"[green]✅ {processed_count}ファイルを匿名化しました[/green]\n\n"
            f"📂 {airlock_path.relative_to(project_dir)}/data/\n"
            f"{file_list}\n\n"
            f"[bold]🚀 Claude Code を起動するには:[/bold]\n"
            f"   [cyan]cd {airlock_path} && claude[/cyan]\n\n"
            f"[bold]📥 結果を一括復元するには:[/bold]\n"
            f"   [cyan]dataairlock workspace {project_dir} --restore-all[/cyan]",
            title="🔒 完了",
        ))
        raise typer.Exit(0)

    # --add オプション（デフォルト動作）
    if add is None and add_all is None:
        console.print("[yellow]使用方法: dataairlock workspace <project_dir> --add <file>[/yellow]")
        console.print("  または: dataairlock workspace <project_dir> --add-all <folder>")
        console.print("  または: dataairlock workspace <project_dir> --status")
        raise typer.Exit(0)

    # ファイル追加処理
    add_path = project_dir / add if not add.is_absolute() else add
    if not add_path.exists():
        console.print(f"[red]エラー: ファイルが見つかりません: {add_path}[/red]")
        raise typer.Exit(1)

    file_ext = add_path.suffix.lower()
    is_document = file_ext in DOCUMENT_EXTENSIONS
    is_spreadsheet = file_ext in SUPPORTED_EXTENSIONS

    if not is_document and not is_spreadsheet:
        console.print(f"[red]エラー: サポートされていないファイル形式: {file_ext}[/red]")
        console.print("  対応形式: .csv, .xlsx, .xls, .docx, .pptx")
        raise typer.Exit(1)

    file_type_str = {
        ".docx": "Word",
        ".pptx": "PowerPoint",
        ".csv": "CSV",
        ".xlsx": "Excel",
        ".xls": "Excel",
    }.get(file_ext, "ファイル")

    console.print(Panel(
        f"[bold cyan]DataAirlock Workspace[/bold cyan]\n\n"
        f"📁 プロジェクト: {project_dir}\n"
        f"📄 追加ファイル: {add} ({file_type_str})",
        title="🔒 セキュアワークスペース",
    ))

    # ドキュメントファイルの場合
    if is_document:
        # スキャン
        try:
            scan_result = scan_document(add_path)
        except Exception as e:
            console.print(f"[red]エラー: ファイルの読み込みに失敗しました: {e}[/red]")
            raise typer.Exit(1)

        if scan_result.total_matches == 0:
            console.print("[green]✓ 個人情報は検出されませんでした[/green]")
            console.print("  データはそのまま安全に使用できます")
            raise typer.Exit(0)

        console.print(f"\n[yellow]⚠️  {scan_result.total_matches}件の個人情報を検出しました[/yellow]\n")

        console.print("[bold]🔍 検出されたPII:[/bold]")
        for pii_type, count in scan_result.pii_by_type.items():
            console.print(f"  - {pii_type}: {count}件")

        # サンプル表示
        if scan_result.sample_matches:
            console.print("\n[bold]📝 サンプル:[/bold]")
            for match in scan_result.sample_matches[:5]:
                console.print(f"  [yellow]{match.original}[/yellow] ({match.pii_type.value})")

        # 戦略選択
        console.print()
        strategy = Prompt.ask(
            "匿名化戦略",
            choices=["r", "g"],
            default="r",
        )
        strategy_map = {"r": "replace", "g": "generalize"}
        selected_strategy = strategy_map[strategy]

        # パスワード取得
        config = _load_workspace_config(project_dir)
        is_new_workspace = config is None

        if password is None:
            console.print()
            password = get_password_interactive(confirm=is_new_workspace)

        # ワークスペース初期化
        airlock_path = _init_workspace(project_dir)

        if config is None:
            config = {
                "created_at": datetime.now().isoformat(),
                "source_directory": str(project_dir),
                "files": {},
            }

        # 匿名化実行
        console.print("\n[bold]匿名化を実行中...[/bold]")

        file_stem = add_path.stem
        output_ext = add_path.suffix
        data_output = airlock_path / AIRLOCK_DATA_DIR / f"{file_stem}{output_ext}"
        mapping_output = _get_mappings_path(project_dir) / f"{file_stem}.mapping.enc"

        try:
            result, mapping = anonymize_document(add_path, data_output, selected_strategy)  # type: ignore
            save_mapping(mapping, mapping_output, password)
        except Exception as e:
            console.print(f"[red]エラー: 匿名化に失敗しました: {e}[/red]")
            raise typer.Exit(1)

        # 設定更新
        pii_types_found = list(scan_result.pii_by_type.keys())
        config["files"][file_stem] = {
            "name": f"{file_stem}{output_ext}",
            "original": str(add),
            "file_type": "document",
            "pii_types": pii_types_found,
            "pii_count": scan_result.total_matches,
        }
        _save_workspace_config(project_dir, config)

        # ドキュメント生成用のファイル情報
        files_info = [
            {
                "name": info["name"],
                "original": info["original"],
                "pii_columns": info.get("pii_columns", info.get("pii_types", [])),
            }
            for info in config["files"].values()
        ]

        # README.md生成（汎用）
        readme_path = airlock_path / "README.md"
        readme_path.write_text(_generate_airlock_readme(airlock_path, files_info), encoding="utf-8")

        # CLAUDE.md生成（Claude Code用）
        claude_md_path = airlock_path / "CLAUDE.md"
        claude_md_path.write_text(_generate_claude_md(files_info), encoding="utf-8")

        # SYSTEM_PROMPT.md生成（汎用LLMツール用）
        system_prompt_path = airlock_path / "SYSTEM_PROMPT.md"
        system_prompt_path.write_text(_generate_system_prompt_md(files_info), encoding="utf-8")

        # PROMPT.md生成（分析依頼テンプレート）
        prompt_path = airlock_path / "PROMPT.md"
        prompt_path.write_text(_generate_prompt_md(files_info), encoding="utf-8")

        # 完了メッセージ
        console.print()
        console.print(Panel(
            f"[green]✅ ワークスペースを{'作成' if is_new_workspace else '更新'}しました[/green]\n\n"
            f"📂 {airlock_path.relative_to(project_dir)}/\n"
            f"├── {AIRLOCK_DATA_DIR}/{file_stem}{output_ext}      [dim]# 匿名化済み[/dim]\n"
            f"├── {AIRLOCK_OUTPUT_DIR}/              [dim]# 結果出力先[/dim]\n"
            f"├── CLAUDE.md\n"
            f"├── SYSTEM_PROMPT.md\n"
            f"├── PROMPT.md\n"
            f"└── README.md\n\n"
            f"📂 {AIRLOCK_MAPPINGS_DIR}/\n"
            f"└── {file_stem}.mapping.enc  [dim]# 復元用（Git除外）[/dim]\n\n"
            f"  置換数: {result.total_matches}件\n\n"
            f"[bold]🚀 Claude Code を起動するには:[/bold]\n"
            f"   [cyan]cd {airlock_path} && claude[/cyan]\n\n"
            f"[bold]📥 結果を復元するには:[/bold]\n"
            f"   [cyan]dataairlock restore-doc {data_output} -m {mapping_output}[/cyan]",
            title="🔒 完了",
        ))
        raise typer.Exit(0)

    # スプレッドシートファイルの場合（従来の処理）
    try:
        df = load_dataframe(add_path)
    except Exception as e:
        console.print(f"[red]エラー: ファイルの読み込みに失敗しました: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"  📊 {len(df):,}行 × {len(df.columns)}列\n")

    # PII検出
    pii_columns = detect_pii_columns(df)

    if not pii_columns:
        console.print("[green]✓ 個人情報は検出されませんでした[/green]")
        console.print("  データはそのまま安全に使用できます")
        raise typer.Exit(0)

    console.print("[bold]🔍 PII検出結果:[/bold]")

    # 各列の処理方法を対話的に決定
    column_actions: dict[str, str] = {}

    for col_name, result in pii_columns.items():
        samples = ", ".join(result.sample_values[:2]) if result.sample_values else "N/A"
        confidence = get_confidence_symbol(result.confidence)

        console.print(f"  [yellow]⚠️[/yellow]  [cyan]{col_name}[/cyan] [{confidence}] {result.pii_type.value}")
        console.print(f"      サンプル: {samples}")

        # デフォルト設定
        default = "r"
        if result.pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
            default = "g"

        action = Prompt.ask(
            "      → (r)eplace/(g)eneralize/(d)elete/(s)kip",
            choices=["r", "g", "d", "s"],
            default=default,
        )
        column_actions[col_name] = {"r": "replace", "g": "generalize", "d": "delete", "s": "skip"}[action]

    # スキップ以外の列がない場合
    columns_to_process = {k: v for k, v in column_actions.items() if v != "skip"}
    if not columns_to_process:
        console.print("[yellow]処理対象の列がありません[/yellow]")
        raise typer.Exit(0)

    # パスワード取得（既存ワークスペースがある場合は確認なし）
    config = _load_workspace_config(project_dir)
    is_new_workspace = config is None

    if password is None:
        console.print()
        password = get_password_interactive(confirm=is_new_workspace)

    # ワークスペース初期化
    airlock_path = _init_workspace(project_dir)

    # 設定読み込みまたは初期化
    if config is None:
        config = {
            "created_at": datetime.now().isoformat(),
            "source_directory": str(project_dir),
            "files": {},
        }

    # 匿名化実行
    console.print("\n[bold]匿名化を実行中...[/bold]")

    anonymized_df = df.copy()
    full_mapping: dict = {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "original_file": str(add),
            "columns_processed": list(columns_to_process.keys()),
        }
    }

    for col_name, action in columns_to_process.items():
        if col_name not in pii_columns:
            continue

        result = pii_columns[col_name]
        single_col_pii = {col_name: result}

        anonymized_df, col_mapping = anonymize_dataframe(
            anonymized_df,
            single_col_pii,
            strategy=action,  # type: ignore
        )

        if col_name in col_mapping:
            full_mapping[col_name] = col_mapping[col_name]

    # ファイル保存
    file_stem = add_path.stem
    data_output = airlock_path / AIRLOCK_DATA_DIR / f"{file_stem}.csv"
    mapping_output = _get_mappings_path(project_dir) / f"{file_stem}.mapping.enc"

    save_dataframe(anonymized_df, data_output)
    save_mapping(full_mapping, mapping_output, password)

    # 設定更新
    config["files"][file_stem] = {
        "name": f"{file_stem}.csv",
        "original": str(add),
        "pii_columns": list(columns_to_process.keys()),
    }
    _save_workspace_config(project_dir, config)

    # ドキュメント生成用のファイル情報
    files_info = [
        {
            "name": info["name"],
            "original": info["original"],
            "pii_columns": info.get("pii_columns", []),
        }
        for info in config["files"].values()
    ]

    # README.md生成（汎用）
    readme_path = airlock_path / "README.md"
    readme_path.write_text(_generate_airlock_readme(airlock_path, files_info), encoding="utf-8")

    # CLAUDE.md生成（Claude Code用）
    claude_md_path = airlock_path / "CLAUDE.md"
    claude_md_path.write_text(_generate_claude_md(files_info), encoding="utf-8")

    # SYSTEM_PROMPT.md生成（汎用LLMツール用）
    system_prompt_path = airlock_path / "SYSTEM_PROMPT.md"
    system_prompt_path.write_text(_generate_system_prompt_md(files_info), encoding="utf-8")

    # PROMPT.md生成（分析依頼テンプレート）
    prompt_path = airlock_path / "PROMPT.md"
    prompt_path.write_text(_generate_prompt_md(files_info), encoding="utf-8")

    # 完了メッセージ
    console.print()
    console.print(Panel(
        f"[green]✅ ワークスペースを{'作成' if is_new_workspace else '更新'}しました[/green]\n\n"
        f"📂 {airlock_path.relative_to(project_dir)}/\n"
        f"├── {AIRLOCK_DATA_DIR}/{file_stem}.csv      [dim]# 匿名化済み[/dim]\n"
        f"├── {AIRLOCK_OUTPUT_DIR}/              [dim]# 結果出力先[/dim]\n"
        f"├── CLAUDE.md\n"
        f"├── SYSTEM_PROMPT.md\n"
        f"├── PROMPT.md\n"
        f"└── README.md\n\n"
        f"📂 {AIRLOCK_MAPPINGS_DIR}/\n"
        f"└── {file_stem}.mapping.enc  [dim]# 復元用（Git除外）[/dim]\n\n"
        f"[bold]🚀 Claude Code を起動するには:[/bold]\n"
        f"   [cyan]cd {airlock_path} && claude[/cyan]\n\n"
        f"[bold]📥 結果を復元するには:[/bold]\n"
        f"   [cyan]dataairlock workspace {project_dir} --restore output/result.csv[/cyan]",
        title="🔒 完了",
    ))


# =============================================================================
# Chat コマンド（ローカルLLM対話モード）
# =============================================================================

def _build_chat_system_prompt(
    mapping_data: dict | None,
    workspace_config: dict | None,
    current_file: Path | None,
) -> str:
    """チャット用システムプロンプトを構築"""
    prompt_parts = [
        "あなたはDataAirlockのアシスタントです。",
        "匿名化されたデータの分析と、データ処理タスクのサポートを行います。",
        "",
        "# あなたの能力",
        "1. ANON_ID（匿名化ID）と実際の値の照合",
        "2. データ構造の説明",
        "3. Claude Code や Codex に渡すプロンプトの生成・提案",
        "4. 結果ファイルの解釈サポート",
        "",
    ]

    # マッピング情報を追加
    if mapping_data:
        prompt_parts.append("# 利用可能なマッピング情報")
        for col_name, col_info in mapping_data.items():
            if col_name == "metadata":
                continue
            if "values" in col_info:
                values = col_info["values"]
                prompt_parts.append(f"## 列: {col_name}")
                prompt_parts.append(f"  - 匿名化方式: {col_info.get('action', '不明')}")
                prompt_parts.append(f"  - マッピング数: {len(values)}件")
                # サンプルを数件表示
                sample_count = min(5, len(values))
                samples = list(values.items())[:sample_count]
                prompt_parts.append("  - サンプル:")
                for original, anon in samples:
                    prompt_parts.append(f"    - {original} → {anon}")
        prompt_parts.append("")

    # ワークスペース情報を追加
    if workspace_config:
        prompt_parts.append("# ワークスペース情報")
        prompt_parts.append(f"  - 作成日時: {workspace_config.get('created_at', '不明')}")
        files = workspace_config.get("files", {})
        if files:
            prompt_parts.append("  - ファイル:")
            for file_name, file_info in files.items():
                pii_cols = file_info.get("pii_columns", file_info.get("pii_types", []))
                pii_str = f" (匿名化列: {', '.join(pii_cols)})" if pii_cols else ""
                prompt_parts.append(f"    - {file_info.get('name', file_name)}{pii_str}")
        prompt_parts.append("")

    # 現在のファイル情報
    if current_file:
        prompt_parts.append(f"# 現在読み込み中のファイル: {current_file.name}")
        prompt_parts.append("")

    prompt_parts.extend([
        "# 重要な指示",
        "- ANON_ID の照合を求められたら、マッピング情報から対応する値を探して回答してください",
        "- データ分析の提案では、具体的なコード例やプロンプト例を提示してください",
        "- 個人情報の取り扱いには十分注意し、匿名化されたデータを安全に扱うようアドバイスしてください",
        "- 日本語で回答してください",
    ])

    return "\n".join(prompt_parts)


def _load_all_mappings(mappings_dirs: list[Path], password: str) -> dict:
    """すべてのマッピングファイルを読み込む（複数ディレクトリ対応）"""
    all_mappings: dict = {}

    for mappings_dir in mappings_dirs:
        if not mappings_dir.exists():
            continue

        for mapping_file in mappings_dir.glob("*.mapping.enc"):
            try:
                mapping_data = load_mapping(mapping_file, password)
                for col_name, col_info in mapping_data.items():
                    if col_name != "metadata":
                        all_mappings[col_name] = col_info
            except Exception:
                # パスワードが異なるファイルはスキップ
                pass

    return all_mappings


def _get_all_mapping_dirs(project_dir: Path) -> list[Path]:
    """すべてのマッピングディレクトリパスを取得（新旧両方）"""
    return [
        project_dir / AIRLOCK_MAPPINGS_DIR,       # 新: .airlock_mappings/
        project_dir / AIRLOCK_DIR / ".mapping",   # 旧: .airlock/.mapping/
    ]


def _lookup_anon_id(anon_id: str, mappings: dict) -> str | None:
    """ANON_IDから元の値を検索"""
    for col_name, col_info in mappings.items():
        if "values" in col_info:
            for original, anon in col_info["values"].items():
                if anon == anon_id:
                    return f"{original} (列: {col_name})"
    return None


def _lookup_original(original: str, mappings: dict) -> str | None:
    """元の値からANON_IDを検索"""
    for col_name, col_info in mappings.items():
        if "values" in col_info:
            for orig, anon in col_info["values"].items():
                if orig == original:
                    return f"{anon} (列: {col_name})"
    return None


def _describe_data_structure(file_path: Path) -> str:
    """ファイルのデータ構造を説明"""
    try:
        if file_path.suffix.lower() == ".csv":
            df = pd.read_csv(file_path, nrows=10)
        elif file_path.suffix.lower() in [".xlsx", ".xls"]:
            df = pd.read_excel(file_path, nrows=10)
        else:
            return f"サポートされていないファイル形式: {file_path.suffix}"

        lines = [
            f"## ファイル: {file_path.name}",
            f"- 列数: {len(df.columns)}",
            "",
            "### 列情報:",
        ]

        for col in df.columns:
            dtype = str(df[col].dtype)
            sample = str(df[col].iloc[0]) if len(df) > 0 else "N/A"
            if len(sample) > 30:
                sample = sample[:30] + "..."
            lines.append(f"- **{col}** ({dtype}): 例 `{sample}`")

        # ANON_ID列を特定
        anon_cols = [col for col in df.columns if "ANON_" in str(df[col].iloc[0]) if len(df) > 0]
        if anon_cols:
            lines.append("")
            lines.append("### 匿名化された列:")
            for col in anon_cols:
                lines.append(f"- {col}")

        return "\n".join(lines)
    except Exception as e:
        return f"ファイル読み込みエラー: {e}"


def _generate_claude_prompt(task_description: str, workspace_config: dict | None) -> str:
    """Claude Code / Codex 用のプロンプトを生成"""
    prompt_parts = [
        "# タスク",
        task_description,
        "",
    ]

    if workspace_config:
        files = workspace_config.get("files", {})
        if files:
            prompt_parts.append("# 利用可能なデータ")
            prompt_parts.append("")
            prompt_parts.append("| ファイル | 元ファイル | 匿名化列 |")
            prompt_parts.append("|---------|-----------|----------|")
            for file_name, file_info in files.items():
                pii_cols = ", ".join(file_info.get("pii_columns", file_info.get("pii_types", []))) or "なし"
                prompt_parts.append(f"| data/{file_info.get('name', file_name)} | {file_info.get('original', '不明')} | {pii_cols} |")
            prompt_parts.append("")

    prompt_parts.extend([
        "# 重要なルール",
        "",
        "1. `ANON_` で始まるIDはそのまま保持してください",
        "2. 結果は `output/` ディレクトリに保存してください",
        "3. 新しい列を追加してもANON_ID列は削除しないでください",
        "",
        "# 出力形式",
        "",
        "処理結果はCSV形式で `output/` に保存してください。",
    ])

    return "\n".join(prompt_parts)


@app.command()
def chat(
    project_dir: Optional[Path] = typer.Argument(
        None,
        help="プロジェクトディレクトリ（ワークスペースのルート）",
    ),
    password: Optional[str] = typer.Option(
        None,
        "-p", "--password",
        help="マッピングファイルのパスワード",
    ),
    model: str = typer.Option(
        "llama3.1:8b",
        "-m", "--model",
        help="使用するOllamaモデル",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "-f", "--file",
        help="分析対象のファイル",
    ),
):
    """
    ローカルLLM（Ollama）を使った対話モード

    \b
    機能:
      1. ANON_ID ↔ 実名の照合（マッピングを参照）
      2. データ構造の説明
      3. Claude Code / Codex に渡すプロンプトの生成・提案
      4. 結果ファイルの解釈サポート

    \b
    使用例:
      # ワークスペースで起動
      dataairlock chat ./my_project

      # ファイル指定で起動
      dataairlock chat ./my_project -f output/result.csv

      # 別のモデルを使用
      dataairlock chat ./my_project -m llama3.2
    """
    from dataairlock.llm_client import LLMClient

    # Ollamaの接続確認
    try:
        import ollama
        ollama_models = ollama.list()
        available_models = [m.get("name", m.get("model", "")) for m in ollama_models.get("models", [])]
    except Exception as e:
        console.print(f"[red]エラー: Ollamaに接続できません[/red]")
        console.print(f"  {e}")
        console.print()
        console.print("Ollamaを起動してください:")
        console.print("  [cyan]ollama serve[/cyan]")
        raise typer.Exit(1)

    # モデル確認
    if model not in available_models:
        console.print(f"[yellow]警告: モデル '{model}' が見つかりません[/yellow]")
        console.print("  利用可能なモデル:")
        for m in available_models:
            console.print(f"    - {m}")
        console.print()
        console.print(f"モデルをダウンロード:")
        console.print(f"  [cyan]ollama pull {model}[/cyan]")
        raise typer.Exit(1)

    # プロジェクトディレクトリの解決
    if project_dir is None:
        project_dir = Path.cwd()
    project_dir = project_dir.resolve()

    # ワークスペース情報の読み込み
    workspace_config = _load_workspace_config(project_dir)
    mapping_dirs = _get_all_mapping_dirs(project_dir)
    mappings: dict = {}

    # マッピングファイルの存在確認（新旧両方のパスをチェック）
    has_mappings = any(
        mapping_dir.exists() and list(mapping_dir.glob("*.mapping.enc"))
        for mapping_dir in mapping_dirs
    )

    # パスワードが必要な場合
    if has_mappings:
        if password is None:
            console.print("[bold]マッピングファイルを読み込みます[/bold]")
            password = get_password_interactive(confirm=False)

        try:
            mappings = _load_all_mappings(mapping_dirs, password)
        except Exception as e:
            console.print(f"[yellow]警告: マッピングの読み込みに失敗: {e}[/yellow]")

    # 対象ファイルの解決
    current_file: Optional[Path] = None
    if file:
        file_path = project_dir / file if not file.is_absolute() else file
        if file_path.exists():
            current_file = file_path
        else:
            # .airlock内を探す
            airlock_file = _get_airlock_path(project_dir) / file
            if airlock_file.exists():
                current_file = airlock_file

    # LLMクライアント初期化
    llm = LLMClient(model=model)
    system_prompt = _build_chat_system_prompt(mappings, workspace_config, current_file)
    llm.set_system_prompt(system_prompt)

    # ヘッダー表示
    console.print()
    console.print(Panel(
        f"[bold cyan]DataAirlock Chat[/bold cyan]\n\n"
        f"🤖 モデル: {model}\n"
        f"📁 プロジェクト: {project_dir}\n"
        f"🔐 マッピング: {len(mappings)}列" + (f"\n📄 ファイル: {current_file.name}" if current_file else ""),
        title="🔒 ローカルLLM対話モード",
    ))

    # コマンド説明
    console.print()
    console.print("[bold]コマンド:[/bold]")
    console.print("  [cyan]/lookup <ANON_ID or 元の値>[/cyan] - IDの照合")
    console.print("  [cyan]/describe[/cyan] - 現在のファイルの構造を説明")
    console.print("  [cyan]/prompt <タスク説明>[/cyan] - Claude Code用プロンプト生成")
    console.print("  [cyan]/load <ファイルパス>[/cyan] - ファイルを読み込む")
    console.print("  [cyan]/reset[/cyan] - 会話履歴をリセット")
    console.print("  [cyan]/quit[/cyan] または [cyan]exit[/cyan] - 終了")
    console.print()

    # 対話ループ
    while True:
        try:
            user_input = Prompt.ask("[bold green]You[/bold green]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[cyan]終了します[/cyan]")
            break

        if not user_input.strip():
            continue

        user_input = user_input.strip()

        # 終了コマンド
        if user_input.lower() in ["/quit", "/exit", "exit", "quit"]:
            console.print("[cyan]終了します[/cyan]")
            break

        # /lookup コマンド
        if user_input.startswith("/lookup "):
            query = user_input[8:].strip()
            if not query:
                console.print("[yellow]使用方法: /lookup <ANON_ID or 元の値>[/yellow]")
                continue

            # ANON_IDから検索
            result = _lookup_anon_id(query, mappings)
            if result:
                console.print(f"[green]✓[/green] {query} → [bold]{result}[/bold]")
                continue

            # 元の値から検索
            result = _lookup_original(query, mappings)
            if result:
                console.print(f"[green]✓[/green] {query} → [bold]{result}[/bold]")
                continue

            console.print(f"[yellow]'{query}' は見つかりませんでした[/yellow]")
            continue

        # /describe コマンド
        if user_input == "/describe":
            if current_file is None:
                console.print("[yellow]ファイルが読み込まれていません[/yellow]")
                console.print("  使用方法: /load <ファイルパス>")
                continue

            description = _describe_data_structure(current_file)
            console.print()
            console.print(Panel(description, title=f"📊 {current_file.name}"))
            continue

        # /prompt コマンド
        if user_input.startswith("/prompt"):
            task = user_input[7:].strip()
            if not task:
                console.print("[yellow]使用方法: /prompt <タスク説明>[/yellow]")
                console.print("  例: /prompt 患者ごとの診察回数を集計してください")
                continue

            prompt = _generate_claude_prompt(task, workspace_config)
            console.print()
            console.print(Panel(prompt, title="📝 Claude Code 用プロンプト"))
            console.print()
            console.print("[dim]このプロンプトをClaude Codeにコピー＆ペーストしてください[/dim]")
            continue

        # /load コマンド
        if user_input.startswith("/load "):
            file_path_str = user_input[6:].strip()
            if not file_path_str:
                console.print("[yellow]使用方法: /load <ファイルパス>[/yellow]")
                continue

            file_path = Path(file_path_str)
            if not file_path.is_absolute():
                file_path = project_dir / file_path_str

            if not file_path.exists():
                # .airlock内を探す
                airlock_file = _get_airlock_path(project_dir) / file_path_str
                if airlock_file.exists():
                    file_path = airlock_file
                else:
                    console.print(f"[red]ファイルが見つかりません: {file_path_str}[/red]")
                    continue

            current_file = file_path
            console.print(f"[green]✓[/green] {current_file.name} を読み込みました")

            # システムプロンプトを更新
            system_prompt = _build_chat_system_prompt(mappings, workspace_config, current_file)
            llm.set_system_prompt(system_prompt)
            continue

        # /reset コマンド
        if user_input == "/reset":
            llm.reset()
            console.print("[green]✓[/green] 会話履歴をリセットしました")
            continue

        # LLMに送信
        console.print()
        console.print("[bold blue]Assistant[/bold blue]")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task(description="考え中...", total=None)
                response = llm.chat(user_input)

            console.print(response)
        except Exception as e:
            console.print(f"[red]エラー: {e}[/red]")

        console.print()


# =============================================================================
# Wrap コマンド（匿名化レイヤー内でCLIツールを実行）
# =============================================================================

@app.command()
def wrap(
    project_dir: Path = typer.Argument(..., help="プロジェクトディレクトリ"),
    command: Optional[str] = typer.Option(
        None,
        "-c", "--command",
        help="実行するコマンド（未指定なら対話シェル）",
    ),
    auto_restore: bool = typer.Option(
        False,
        "--auto-restore",
        help="終了後に自動で結果を復元",
    ),
    password: Optional[str] = typer.Option(
        None,
        "-p", "--password",
        help="マッピング復号パスワード",
    ),
    shell: bool = typer.Option(
        False,
        "--shell",
        help="対話シェルを起動",
    ),
):
    """
    匿名化レイヤー内でCLIツールを実行

    \b
    ワークスペースの .airlock/ ディレクトリ内でコマンドを実行し、
    終了後に output/ 内の結果を自動検出・復元できます。

    \b
    使用例:
      # 対話シェルを起動
      dataairlock wrap ./my_project --shell

      # Claude Codeを起動
      dataairlock wrap ./my_project -c "claude"

      # 自動復元付きでコマンド実行
      dataairlock wrap ./my_project -c "python analyze.py" --auto-restore

      # 引数付きコマンド
      dataairlock wrap ./my_project -c "claude 'データを分析して'"
    """
    project_dir = project_dir.resolve()

    if not project_dir.exists():
        console.print(f"[red]エラー: ディレクトリが見つかりません: {project_dir}[/red]")
        raise typer.Exit(1)

    # ワークスペースの存在確認
    airlock_path = _get_airlock_path(project_dir)
    if not airlock_path.exists():
        console.print(f"[red]エラー: ワークスペースが見つかりません: {airlock_path}[/red]")
        console.print()
        console.print("先にワークスペースを作成してください:")
        console.print(f"  [cyan]dataairlock workspace {project_dir} --add <file>[/cyan]")
        raise typer.Exit(1)

    # 設定読み込み
    workspace_config = _load_workspace_config(project_dir)
    if not workspace_config:
        console.print("[red]エラー: ワークスペース設定が見つかりません[/red]")
        raise typer.Exit(1)

    # ディレクトリパス
    data_path = airlock_path / AIRLOCK_DATA_DIR
    output_path = airlock_path / AIRLOCK_OUTPUT_DIR

    if not data_path.exists():
        console.print(f"[red]エラー: データディレクトリが見つかりません: {data_path}[/red]")
        raise typer.Exit(1)

    # output/ ディレクトリがなければ作成
    output_path.mkdir(parents=True, exist_ok=True)

    # 実行前の output/ 内ファイルを記録
    output_files_before = set(output_path.glob("**/*"))

    # auto-restore の場合はパスワードが必要
    if auto_restore:
        mapping_dirs = _get_all_mapping_dirs(project_dir)
        has_mappings = any(
            mapping_dir.exists() and list(mapping_dir.glob("*.mapping.enc"))
            for mapping_dir in mapping_dirs
        )

        if has_mappings and password is None:
            console.print("[bold]復元用パスワードを入力してください[/bold]")
            password = get_password_interactive(confirm=False)

    # ヘッダー表示
    console.print()
    console.print(Panel(
        f"[bold cyan]DataAirlock Wrap[/bold cyan]\n\n"
        f"📁 プロジェクト: {project_dir}\n"
        f"📂 作業ディレクトリ: {airlock_path}\n"
        f"📄 データ: {data_path}\n"
        f"📤 出力先: {output_path}" +
        (f"\n🔄 自動復元: 有効" if auto_restore else ""),
        title="🔒 匿名化レイヤー",
    ))

    # 環境変数を設定
    env = os.environ.copy()
    env["DATAAIRLOCK_PROJECT"] = str(project_dir)
    env["DATAAIRLOCK_WORKSPACE"] = str(airlock_path)
    env["DATAAIRLOCK_DATA"] = str(data_path)
    env["DATAAIRLOCK_OUTPUT"] = str(output_path)

    # コマンド実行
    console.print()

    if command:
        console.print(f"[bold]実行中:[/bold] {command}")
        console.print()

        # シェル経由でコマンドを実行
        result = subprocess.run(
            command,
            shell=True,
            cwd=str(airlock_path),
            env=env,
        )
        exit_code = result.returncode

    elif shell:
        # 対話シェルを起動
        shell_cmd = os.environ.get("SHELL", "/bin/bash")
        console.print(f"[bold]対話シェルを起動中...[/bold] ({shell_cmd})")
        console.print("[dim]終了するには 'exit' を入力してください[/dim]")
        console.print()

        result = subprocess.run(
            [shell_cmd],
            cwd=str(airlock_path),
            env=env,
        )
        exit_code = result.returncode

    else:
        # コマンドもシェルも指定されていない場合
        console.print("[yellow]コマンドが指定されていません[/yellow]")
        console.print()
        console.print("使用方法:")
        console.print(f"  [cyan]dataairlock wrap {project_dir} -c \"claude\"[/cyan]")
        console.print(f"  [cyan]dataairlock wrap {project_dir} --shell[/cyan]")
        raise typer.Exit(0)

    # 終了後の処理
    console.print()

    # output/ 内の新しいファイルを検出
    output_files_after = set(output_path.glob("**/*"))
    new_files = output_files_after - output_files_before
    new_files = [f for f in new_files if f.is_file()]

    if new_files:
        console.print(f"[bold]📤 新しい出力ファイル: {len(new_files)}件[/bold]")
        for f in new_files[:10]:  # 最大10件表示
            rel_path = f.relative_to(output_path)
            console.print(f"  - {rel_path}")
        if len(new_files) > 10:
            console.print(f"  ... 他 {len(new_files) - 10} 件")
        console.print()

        if auto_restore:
            # 自動復元
            console.print("[bold]結果を復元中...[/bold]")

            mapping_dirs = _get_all_mapping_dirs(project_dir)
            all_mappings: dict = {}

            if password:
                try:
                    all_mappings = _load_all_mappings(mapping_dirs, password)
                except Exception as e:
                    console.print(f"[yellow]警告: マッピングの読み込みに失敗: {e}[/yellow]")

            # 復元実行
            results_dir = project_dir / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            restored_count = 0

            for csv_file in output_path.glob("**/*.csv"):
                try:
                    rel_path = csv_file.relative_to(output_path)
                    output_file = results_dir / rel_path
                    output_file.parent.mkdir(parents=True, exist_ok=True)

                    df = pd.read_csv(csv_file)
                    restored_df = deanonymize_dataframe(df, all_mappings)
                    save_dataframe(restored_df, output_file)
                    console.print(f"  [green]✓[/green] {rel_path}")
                    restored_count += 1
                except Exception as e:
                    rel_path = csv_file.relative_to(output_path)
                    console.print(f"  [red]✗[/red] {rel_path}: {e}")

            if restored_count > 0:
                console.print()
                console.print(Panel(
                    f"[green]✅ {restored_count}ファイルを復元しました[/green]\n\n"
                    f"📂 results/",
                    title="🔓 完了",
                ))
            else:
                console.print("[yellow]復元対象のCSVファイルがありませんでした[/yellow]")
        else:
            # 復元方法を案内
            console.print("[bold]結果を復元するには:[/bold]")
            console.print(f"  [cyan]dataairlock workspace {project_dir} --restore-all -p <password>[/cyan]")
    else:
        console.print("[dim]新しい出力ファイルはありませんでした[/dim]")

    # 終了コード表示
    if exit_code != 0:
        console.print(f"[yellow]コマンドは終了コード {exit_code} で終了しました[/yellow]")

    raise typer.Exit(exit_code)


@app.command()
def start():
    """
    対話型TUIを起動

    すべての操作を対話形式で実行できます。
    """
    from dataairlock.tui import run_tui
    run_tui()


# プロファイル管理コマンド
profile_app = typer.Typer(
    name="profile",
    help="PII処理プロファイルの管理",
)
app.add_typer(profile_app, name="profile")


@profile_app.command(name="list")
def profile_list():
    """
    保存されたプロファイル一覧を表示
    """
    manager = ProfileManager()
    profiles = manager.list_profiles()

    if not profiles:
        console.print("[yellow]保存されたプロファイルがありません[/yellow]")
        console.print(f"[dim]プロファイルは {manager.profile_dir} に保存されます[/dim]")
        return

    table = Table(title="プロファイル一覧", show_header=True)
    table.add_column("名前")
    table.add_column("列ルール数")
    table.add_column("PIIタイプ数")
    table.add_column("最終使用")
    table.add_column("更新日")

    for p in profiles:
        last_used = p.last_used_at.strftime("%Y-%m-%d") if p.last_used_at else "-"
        updated = p.updated_at.strftime("%Y-%m-%d") if p.updated_at else "-"
        table.add_row(
            p.name,
            str(len(p.column_rules)),
            str(len(p.pii_type_defaults)),
            last_used,
            updated,
        )

    console.print(table)
    console.print(f"\n[dim]保存先: {manager.profile_dir}[/dim]")


@profile_app.command(name="show")
def profile_show(
    name: str = typer.Argument(..., help="プロファイル名"),
):
    """
    プロファイルの詳細を表示
    """
    manager = ProfileManager()
    profile = manager.load(name)

    if not profile:
        console.print(f"[red]プロファイル「{name}」が見つかりません[/red]")
        raise typer.Exit(1)

    console.print(Panel(f"[bold]{profile.name}[/bold]", title="プロファイル"))

    if profile.column_rules:
        console.print("\n[bold]列ルール:[/bold]")
        for col, action in profile.column_rules.items():
            console.print(f"  {col}: {action}")

    if profile.pii_type_defaults:
        console.print("\n[bold]PIIタイプデフォルト:[/bold]")
        for pii_type, action in profile.pii_type_defaults.items():
            console.print(f"  {pii_type}: {action}")

    console.print(f"\n[dim]作成日: {profile.created_at.strftime('%Y-%m-%d %H:%M')}[/dim]")
    if profile.updated_at:
        console.print(f"[dim]更新日: {profile.updated_at.strftime('%Y-%m-%d %H:%M')}[/dim]")
    if profile.last_used_at:
        console.print(f"[dim]最終使用: {profile.last_used_at.strftime('%Y-%m-%d %H:%M')}[/dim]")


@profile_app.command(name="delete")
def profile_delete(
    name: str = typer.Argument(..., help="削除するプロファイル名"),
    force: bool = typer.Option(False, "--force", "-f", help="確認なしで削除"),
):
    """
    プロファイルを削除
    """
    manager = ProfileManager()

    if not manager.exists(name):
        console.print(f"[red]プロファイル「{name}」が見つかりません[/red]")
        raise typer.Exit(1)

    if not force:
        confirm = Confirm.ask(f"プロファイル「{name}」を削除しますか？")
        if not confirm:
            console.print("[yellow]キャンセルしました[/yellow]")
            return

    if manager.delete(name):
        console.print(f"[green]✓ プロファイル「{name}」を削除しました[/green]")
    else:
        console.print(f"[red]削除に失敗しました[/red]")
        raise typer.Exit(1)


@profile_app.command(name="export")
def profile_export(
    name: str = typer.Argument(..., help="エクスポートするプロファイル名"),
    output: Path = typer.Option(None, "--output", "-o", help="出力ファイルパス"),
):
    """
    プロファイルをJSONファイルにエクスポート（チーム共有用）
    """
    manager = ProfileManager()

    if not manager.exists(name):
        console.print(f"[red]プロファイル「{name}」が見つかりません[/red]")
        raise typer.Exit(1)

    if output is None:
        output = Path(f"{name}_profile.json")

    if manager.export_profile(name, output):
        console.print(f"[green]✓ プロファイルを {output} にエクスポートしました[/green]")
    else:
        console.print(f"[red]エクスポートに失敗しました[/red]")
        raise typer.Exit(1)


@profile_app.command(name="import")
def profile_import(
    input_file: Path = typer.Argument(..., help="インポートするJSONファイル"),
    overwrite: bool = typer.Option(False, "--overwrite", help="既存プロファイルを上書き"),
):
    """
    JSONファイルからプロファイルをインポート
    """
    manager = ProfileManager()

    if not input_file.exists():
        console.print(f"[red]ファイルが見つかりません: {input_file}[/red]")
        raise typer.Exit(1)

    profile = manager.import_profile(input_file, overwrite=overwrite)
    if profile:
        console.print(f"[green]✓ プロファイル「{profile.name}」をインポートしました[/green]")
    else:
        console.print(f"[red]インポートに失敗しました（同名のプロファイルが存在する場合は --overwrite を指定）[/red]")
        raise typer.Exit(1)


@profile_app.command(name="create-default")
def profile_create_default():
    """
    デフォルトプロファイルを作成
    """
    manager = ProfileManager()

    if manager.exists("default"):
        confirm = Confirm.ask("デフォルトプロファイルは既に存在します。上書きしますか？")
        if not confirm:
            console.print("[yellow]キャンセルしました[/yellow]")
            return

    profile = manager.create_default_profile()
    console.print(f"[green]✓ デフォルトプロファイルを作成しました[/green]")
    console.print(f"[dim]保存先: {manager._get_profile_path(profile.name)}[/dim]")


if __name__ == "__main__":
    app()
