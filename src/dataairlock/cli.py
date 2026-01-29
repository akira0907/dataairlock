"""DataAirlock CLI アプリケーション"""

import getpass
import json
import shutil
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

app = typer.Typer(
    name="dataairlock",
    help="個人情報を匿名化してクラウドLLMに安全に渡すためのCLIツール",
    no_args_is_help=True,
)

console = Console()

# ワークスペース設定
AIRLOCK_DIR = ".airlock"
AIRLOCK_DATA_DIR = "data"
AIRLOCK_MAPPING_DIR = ".mapping"
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
):
    """
    PIIを検出して表示（匿名化は実行しない）
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

    # PII検出
    pii_columns = detect_pii_columns(df)

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
):
    """
    ファイルを匿名化する
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

    # PII検出
    pii_columns = detect_pii_columns(df)

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
    return """# DataAirlock - 機密データ
# マッピングファイル（復元用キー）
.mapping/
*.enc

# ローカル設定
.password
airlock.json
"""


def _generate_airlock_readme(airlock_path: Path) -> str:
    """airlock用README.mdを生成"""
    return f"""# DataAirlock Workspace

このディレクトリはDataAirlockによって生成されたセキュアな作業環境です。

## 構造

- `data/` - 匿名化済みデータ（Claude Codeに渡してOK）
- `output/` - Claude Codeの出力先
- `.mapping/` - 復元用マッピング（⚠️ 機密・Git除外）

## 使い方

1. このディレクトリで Claude Code を起動:
   ```bash
   cd {airlock_path} && claude
   ```

2. `data/` 内のファイルを分析

3. 結果を `output/` に保存

4. プロジェクトルートで復元:
   ```bash
   dataairlock workspace ../ --restore output/result.csv
   ```

## 注意事項

- `ANON_` で始まるIDは匿名化された値です。そのまま保持してください
- `.mapping/` ディレクトリは絶対にGitにコミットしないでください
- 結果ファイルは `output/` に保存することを推奨します
"""


def _generate_prompt_md(files_info: list[dict]) -> str:
    """PROMPT.mdを生成"""
    files_table = "| ファイル | 元ファイル | 匿名化列 |\n|---------|-----------|----------|\n"
    for info in files_info:
        pii_cols = ", ".join(info.get("pii_columns", [])) or "なし"
        files_table += f"| data/{info['name']} | {info['original']} | {pii_cols} |\n"

    return f"""# 作業環境

このディレクトリには匿名化済みデータが含まれています。

## 利用可能なデータ

{files_table}

## 重要なルール

1. `ANON_` で始まるIDはそのまま保持してください
2. 結果は `output/` ディレクトリに保存してください
3. 新しい列を追加してもANON_ID列は削除しないでください

## 依頼内容

[ここに分析依頼を記述]
"""


def _init_workspace(directory: Path) -> Path:
    """ワークスペースを初期化"""
    airlock_path = _get_airlock_path(directory)
    data_path = airlock_path / AIRLOCK_DATA_DIR
    mapping_path = airlock_path / AIRLOCK_MAPPING_DIR
    output_path = airlock_path / AIRLOCK_OUTPUT_DIR

    # ディレクトリ作成
    data_path.mkdir(parents=True, exist_ok=True)
    mapping_path.mkdir(parents=True, exist_ok=True)
    output_path.mkdir(parents=True, exist_ok=True)

    # .gitignore作成
    gitignore_path = airlock_path / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text(_generate_airlock_gitignore(), encoding="utf-8")

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
        if not airlock_path.exists():
            console.print(f"[yellow]ワークスペースが見つかりません: {airlock_path}[/yellow]")
            raise typer.Exit(0)

        console.print(f"[yellow]警告: {airlock_path} を削除します[/yellow]")
        if not Confirm.ask("本当に削除しますか？"):
            console.print("キャンセルしました")
            raise typer.Exit(0)

        shutil.rmtree(airlock_path)
        console.print(f"[green]✓ {airlock_path} を削除しました[/green]")
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
        mapping_branch = tree.add(f"📁 {AIRLOCK_MAPPING_DIR}/ [dim](Git除外)[/dim]")
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
        mapping_dir = airlock_path / AIRLOCK_MAPPING_DIR

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
        mapping_dir = airlock_path / AIRLOCK_MAPPING_DIR

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
            mapping_output = airlock_path / AIRLOCK_MAPPING_DIR / f"{file_stem}.mapping.enc"

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

        # README.md生成
        readme_path = airlock_path / "README.md"
        readme_path.write_text(_generate_airlock_readme(airlock_path), encoding="utf-8")

        # PROMPT.md生成
        files_info = [
            {
                "name": info["name"],
                "original": info["original"],
                "pii_columns": info.get("pii_columns", []),
            }
            for info in config["files"].values()
        ]
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
        mapping_output = airlock_path / AIRLOCK_MAPPING_DIR / f"{file_stem}.mapping.enc"

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

        # README.md生成
        readme_path = airlock_path / "README.md"
        readme_path.write_text(_generate_airlock_readme(airlock_path), encoding="utf-8")

        # PROMPT.md生成
        files_info = [
            {
                "name": info["name"],
                "original": info["original"],
                "pii_columns": info.get("pii_columns", info.get("pii_types", [])),
            }
            for info in config["files"].values()
        ]
        prompt_path = airlock_path / "PROMPT.md"
        prompt_path.write_text(_generate_prompt_md(files_info), encoding="utf-8")

        # 完了メッセージ
        console.print()
        console.print(Panel(
            f"[green]✅ ワークスペースを{'作成' if is_new_workspace else '更新'}しました[/green]\n\n"
            f"📂 {airlock_path.relative_to(project_dir)}/\n"
            f"├── {AIRLOCK_DATA_DIR}/{file_stem}{output_ext}      [dim]# 匿名化済み[/dim]\n"
            f"├── {AIRLOCK_MAPPING_DIR}/{file_stem}.mapping.enc\n"
            f"├── {AIRLOCK_OUTPUT_DIR}/              [dim]# 結果出力先[/dim]\n"
            f"├── PROMPT.md\n"
            f"└── README.md\n\n"
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
    mapping_output = airlock_path / AIRLOCK_MAPPING_DIR / f"{file_stem}.mapping.enc"

    save_dataframe(anonymized_df, data_output)
    save_mapping(full_mapping, mapping_output, password)

    # 設定更新
    config["files"][file_stem] = {
        "name": f"{file_stem}.csv",
        "original": str(add),
        "pii_columns": list(columns_to_process.keys()),
    }
    _save_workspace_config(project_dir, config)

    # README.md生成
    readme_path = airlock_path / "README.md"
    readme_path.write_text(_generate_airlock_readme(airlock_path), encoding="utf-8")

    # PROMPT.md生成
    files_info = [
        {
            "name": info["name"],
            "original": info["original"],
            "pii_columns": info.get("pii_columns", []),
        }
        for info in config["files"].values()
    ]
    prompt_path = airlock_path / "PROMPT.md"
    prompt_path.write_text(_generate_prompt_md(files_info), encoding="utf-8")

    # 完了メッセージ
    console.print()
    console.print(Panel(
        f"[green]✅ ワークスペースを{'作成' if is_new_workspace else '更新'}しました[/green]\n\n"
        f"📂 {airlock_path.relative_to(project_dir)}/\n"
        f"├── {AIRLOCK_DATA_DIR}/{file_stem}.csv      [dim]# 匿名化済み[/dim]\n"
        f"├── {AIRLOCK_MAPPING_DIR}/{file_stem}.mapping.enc\n"
        f"├── {AIRLOCK_OUTPUT_DIR}/              [dim]# 結果出力先[/dim]\n"
        f"├── PROMPT.md\n"
        f"└── README.md\n\n"
        f"[bold]🚀 Claude Code を起動するには:[/bold]\n"
        f"   [cyan]cd {airlock_path} && claude[/cyan]\n\n"
        f"[bold]📥 結果を復元するには:[/bold]\n"
        f"   [cyan]dataairlock workspace {project_dir} --restore output/result.csv[/cyan]",
        title="🔒 完了",
    ))


if __name__ == "__main__":
    app()
