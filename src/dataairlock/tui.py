"""DataAirlock 完全対話型TUI"""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dataairlock.anonymizer import (
    PIIType,
    anonymize_dataframe,
    check_collision,
    deanonymize_dataframe,
    detect_pii_columns,
    load_mapping,
    save_mapping,
)

console = Console()

# ワークスペース設定（cli.pyと共通）
AIRLOCK_DIR = ".airlock"
AIRLOCK_DATA_DIR = "data"
AIRLOCK_MAPPINGS_DIR = ".airlock_mappings"
AIRLOCK_OUTPUT_DIR = "output"
AIRLOCK_CONFIG = "airlock.json"
SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".xls"}

# カスタムスタイル
custom_style = Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:green'),
])


def clear_screen():
    """画面クリア"""
    os.system('cls' if os.name == 'nt' else 'clear')


def show_header():
    """ヘッダー表示"""
    console.print()
    console.print(Panel(
        "[bold cyan]DataAirlock[/bold cyan]\n"
        "機密データを安全にクラウドLLMへ",
        title="🔒",
        border_style="cyan",
    ))
    console.print()


def _get_airlock_path(directory: Path) -> Path:
    """airlockディレクトリのパスを取得"""
    return directory / AIRLOCK_DIR


def _get_mappings_path(directory: Path) -> Path:
    """マッピングディレクトリのパスを取得（プロジェクトルート）"""
    return directory / AIRLOCK_MAPPINGS_DIR


def _get_config_path(directory: Path) -> Path:
    """設定ファイルのパスを取得"""
    return _get_airlock_path(directory) / AIRLOCK_CONFIG


def _load_workspace_config(directory: Path) -> dict | None:
    """ワークスペース設定を読み込み"""
    import json
    config_path = _get_config_path(directory)
    if not config_path.exists():
        return None
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_workspace_config(directory: Path, config: dict) -> None:
    """ワークスペース設定を保存"""
    import json
    config_path = _get_config_path(directory)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def _generate_airlock_gitignore() -> str:
    """airlock用.gitignoreを生成"""
    return """# DataAirlock - ローカル設定
airlock.json
"""


def _generate_mappings_gitignore() -> str:
    """マッピングディレクトリ用.gitignore（全ファイル除外）"""
    return "*\n"


def _init_workspace(directory: Path) -> Path:
    """ワークスペースを初期化"""
    airlock_path = _get_airlock_path(directory)
    data_path = airlock_path / AIRLOCK_DATA_DIR
    mappings_path = _get_mappings_path(directory)
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


def load_dataframe(file_path: Path) -> pd.DataFrame:
    """ファイルをDataFrameとして読み込む"""
    if file_path.suffix.lower() == ".csv":
        return pd.read_csv(file_path)
    elif file_path.suffix.lower() in [".xlsx", ".xls"]:
        return pd.read_excel(file_path)
    else:
        raise ValueError(f"サポートされていないファイル形式: {file_path.suffix}")


def save_dataframe(df: pd.DataFrame, file_path: Path) -> None:
    """DataFrameをUTF-8 BOM付きCSVとして保存"""
    with open(file_path, "wb") as f:
        f.write(b'\xef\xbb\xbf')
        f.write(df.to_csv(index=False).encode('utf-8'))


def show_status(project_dir: Path) -> bool:
    """ワークスペースのステータス表示"""
    config = _load_workspace_config(project_dir)
    if not config:
        console.print("[yellow]ワークスペースがありません[/yellow]")
        return False

    console.print(f"[bold]📁 プロジェクト:[/bold] {project_dir}")
    console.print(f"[bold]📅 作成日時:[/bold] {config.get('created_at', '不明')}")
    console.print()

    # ファイル一覧
    table = Table(title="登録ファイル", show_header=True)
    table.add_column("ファイル名")
    table.add_column("匿名化列")

    for file_name, file_info in config.get("files", {}).items():
        pii_cols = ", ".join(file_info.get("pii_columns", [])) or "なし"
        table.add_row(file_info.get("name", file_name), pii_cols)

    console.print(table)
    return True


def select_file() -> Optional[Path]:
    """ファイル選択（パス入力）"""
    file_path = questionary.path(
        "ファイルを選択（パスを入力、またはドラッグ＆ドロップ）:",
        style=custom_style,
    ).ask()

    if not file_path:
        return None

    path = Path(file_path.strip().strip("'\""))
    if not path.exists():
        console.print(f"[red]エラー: ファイルが見つかりません: {path}[/red]")
        return None

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        console.print(f"[red]エラー: サポートされていない形式: {path.suffix}[/red]")
        console.print(f"  対応形式: {', '.join(SUPPORTED_EXTENSIONS)}")
        return None

    return path


def select_pii_actions(pii_columns: dict) -> dict:
    """PII列の処理方法を選択"""
    actions = {}

    for col_name, result in pii_columns.items():
        samples = ", ".join(result.sample_values[:2]) if result.sample_values else "N/A"

        console.print(f"\n[yellow]⚠️[/yellow] [cyan]{col_name}[/cyan] ({result.pii_type.value})")
        console.print(f"   サンプル: {samples}")

        # デフォルト値を決定
        default_choice = "🔄 置換（PERSON_001形式）← おすすめ"
        if result.pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
            default_choice = "📊 一般化（年代・都道府県等）"

        choice = questionary.select(
            f"「{col_name}」の処理方法:",
            choices=[
                "🔄 置換（PERSON_001形式）← おすすめ",
                "📊 一般化（年代・都道府県等）",
                "🗑️ 削除",
                "⏭️ スキップ（処理しない）",
            ],
            default=default_choice,
            style=custom_style,
        ).ask()

        if choice is None:
            return {}

        action_map = {
            "🔄 置換（PERSON_001形式）← おすすめ": "replace",
            "📊 一般化（年代・都道府県等）": "generalize",
            "🗑️ 削除": "delete",
            "⏭️ スキップ（処理しない）": "skip",
        }
        actions[col_name] = action_map[choice]

    return actions


def get_password(confirm: bool = True) -> Optional[str]:
    """パスワード入力"""
    password = questionary.password(
        "パスワードを入力:",
        style=custom_style,
    ).ask()

    if not password:
        return None

    if confirm:
        password_confirm = questionary.password(
            "パスワード（確認）:",
            style=custom_style,
        ).ask()

        if password != password_confirm:
            console.print("[red]パスワードが一致しません[/red]")
            return None

    if len(password) < 8:
        console.print("[yellow]警告: パスワードは8文字以上を推奨します[/yellow]")

    return password


def launch_claude_code(airlock_path: Path) -> int:
    """Claude Code を起動"""
    console.print()
    console.print("[bold]🚀 Claude Code を起動しています...[/bold]")
    console.print(f"   作業ディレクトリ: {airlock_path}")
    console.print()
    console.print("[dim]💡 ヒント: 作業が終わったら /exit で終了してください[/dim]")
    console.print()

    # 環境変数を設定
    env = os.environ.copy()
    env["DATAAIRLOCK_WORKSPACE"] = str(airlock_path)
    env["DATAAIRLOCK_DATA"] = str(airlock_path / "data")
    env["DATAAIRLOCK_OUTPUT"] = str(airlock_path / "output")

    # Claude Code を起動
    try:
        result = subprocess.run(
            ["claude"],
            cwd=str(airlock_path),
            env=env,
        )
        return result.returncode
    except FileNotFoundError:
        console.print("[red]エラー: claude コマンドが見つかりません[/red]")
        console.print("[dim]Claude Code をインストールしてください: https://claude.ai/code[/dim]")
        return 1


def restore_results(project_dir: Path, password: str) -> bool:
    """結果を復元"""
    airlock_path = _get_airlock_path(project_dir)
    output_dir = airlock_path / "output"

    if not output_dir.exists():
        console.print("[yellow]output/ ディレクトリがありません[/yellow]")
        return False

    csv_files = list(output_dir.glob("**/*.csv"))
    if not csv_files:
        console.print("[yellow]復元対象のCSVファイルがありません[/yellow]")
        return False

    # マッピング読み込み
    mapping_dir = _get_mappings_path(project_dir)
    all_mappings: dict = {"metadata": {}}

    if mapping_dir.exists():
        for mapping_file in mapping_dir.glob("*.mapping.enc"):
            try:
                mapping_data = load_mapping(mapping_file, password)
                for col_name, col_info in mapping_data.items():
                    if col_name != "metadata" and isinstance(col_info, dict):
                        all_mappings[col_name] = col_info
            except Exception:
                pass

    if len(all_mappings) <= 1:  # metadata only
        console.print("[red]有効なマッピングが見つかりません（パスワードを確認してください）[/red]")
        return False

    # 復元実行
    results_dir = project_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    console.print("\n[bold]復元を実行中...[/bold]")

    restored_count = 0
    for csv_file in csv_files:
        try:
            rel_path = csv_file.relative_to(output_dir)
            output_path = results_dir / rel_path
            output_path.parent.mkdir(parents=True, exist_ok=True)

            df = pd.read_csv(csv_file)
            restored_df = deanonymize_dataframe(df, all_mappings)
            save_dataframe(restored_df, output_path)
            console.print(f"  [green]✓[/green] {rel_path}")
            restored_count += 1
        except Exception as e:
            console.print(f"  [red]✗[/red] {rel_path}: {e}")

    console.print()
    console.print(Panel(
        f"[green]✅ {restored_count}ファイルを復元しました[/green]\n\n"
        f"📂 {results_dir}/",
        title="🔓 完了",
    ))

    return True


# =============================================================================
# メインメニュー
# =============================================================================

def main_menu() -> Optional[str]:
    """メインメニュー"""
    clear_screen()
    show_header()

    # カレントディレクトリにワークスペースがあるかチェック
    project_dir = Path.cwd()
    has_workspace = (_get_airlock_path(project_dir)).exists()

    if has_workspace:
        choices = [
            "🚀 Claude Code を起動",
            "📁 ファイルを追加",
            "🔓 結果を復元",
            "📋 ステータス確認",
            "🗑️ ワークスペースを削除",
            "🚪 終了",
        ]
    else:
        choices = [
            "📁 新しいプロジェクトを開始",
            "❓ ヘルプ",
            "🚪 終了",
        ]

    choice = questionary.select(
        "何をしますか？",
        choices=choices,
        style=custom_style,
    ).ask()

    return choice


def flow_new_project():
    """新規プロジェクトフロー"""
    project_dir = Path.cwd()

    # ファイル選択
    console.print("\n[bold]📁 ファイルを選択[/bold]")
    file_path = select_file()
    if not file_path:
        return

    # ファイル読み込み
    try:
        df = load_dataframe(file_path)
    except Exception as e:
        console.print(f"[red]エラー: {e}[/red]")
        return

    console.print(f"  📊 {len(df):,}行 × {len(df.columns)}列")

    # 衝突チェック
    warnings = check_collision(df)
    for w in warnings:
        console.print(f"[yellow]{w}[/yellow]")

    # PII検出
    console.print("\n[bold]🔍 PII検出中...[/bold]")
    pii_columns = detect_pii_columns(df)

    if not pii_columns:
        console.print("[green]✓ 個人情報は検出されませんでした[/green]")
        questionary.press_any_key_to_continue().ask()
        return

    console.print(f"[yellow]⚠️ {len(pii_columns)}件の個人情報列を検出しました[/yellow]")

    # 処理方法選択
    column_actions = select_pii_actions(pii_columns)
    if not column_actions:
        return

    # スキップ以外の列がない場合
    columns_to_process = {k: v for k, v in column_actions.items() if v != "skip"}
    if not columns_to_process:
        console.print("[yellow]処理対象の列がありません[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    # パスワード入力
    console.print("\n[bold]🔑 パスワード設定[/bold]")
    password = get_password(confirm=True)
    if not password:
        return

    # 匿名化実行
    console.print("\n[bold]匿名化を実行中...[/bold]")

    airlock_path = _init_workspace(project_dir)

    config = {
        "created_at": datetime.now().isoformat(),
        "source_directory": str(project_dir),
        "files": {},
    }

    anonymized_df = df.copy()
    full_mapping: dict = {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "original_file": str(file_path),
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
            strategy=action,
        )

        if col_name in col_mapping:
            full_mapping[col_name] = col_mapping[col_name]

    # ファイル保存
    file_stem = file_path.stem
    data_output = airlock_path / "data" / f"{file_stem}.csv"
    mapping_output = _get_mappings_path(project_dir) / f"{file_stem}.mapping.enc"

    data_output.parent.mkdir(parents=True, exist_ok=True)
    save_dataframe(anonymized_df, data_output)
    save_mapping(full_mapping, mapping_output, password)

    # 設定保存
    config["files"][file_stem] = {
        "name": f"{file_stem}.csv",
        "original": str(file_path),
        "pii_columns": list(columns_to_process.keys()),
    }
    _save_workspace_config(project_dir, config)

    console.print()
    console.print(Panel(
        "[green]✅ ワークスペース作成完了！[/green]",
        title="🔒",
    ))

    # 次のアクション
    next_action = questionary.select(
        "次のアクションは？",
        choices=[
            "🚀 Claude Code を起動",
            "🔙 メニューに戻る",
        ],
        style=custom_style,
    ).ask()

    if next_action == "🚀 Claude Code を起動":
        flow_launch_claude(password)


def flow_launch_claude(password: Optional[str] = None):
    """Claude Code起動フロー"""
    project_dir = Path.cwd()
    airlock_path = _get_airlock_path(project_dir)

    if not airlock_path.exists():
        console.print("[red]ワークスペースがありません[/red]")
        return

    # Claude Code 起動
    exit_code = launch_claude_code(airlock_path)

    # 終了後
    console.print()

    # 新しい出力ファイルをチェック
    output_dir = airlock_path / "output"
    csv_files = list(output_dir.glob("**/*.csv")) if output_dir.exists() else []

    if csv_files:
        console.print(f"[bold]📤 出力ファイル: {len(csv_files)}件[/bold]")
        for f in csv_files[:5]:
            console.print(f"  - {f.relative_to(output_dir)}")

        # 復元確認
        do_restore = questionary.confirm(
            "結果を復元しますか？",
            default=True,
            style=custom_style,
        ).ask()

        if do_restore:
            if password is None:
                password = get_password(confirm=False)
            if password:
                restore_results(project_dir, password)
    else:
        console.print("[dim]新しい出力ファイルはありませんでした[/dim]")

    questionary.press_any_key_to_continue().ask()


def flow_restore():
    """復元フロー"""
    project_dir = Path.cwd()

    console.print("\n[bold]🔓 結果を復元[/bold]")

    password = get_password(confirm=False)
    if not password:
        return

    restore_results(project_dir, password)
    questionary.press_any_key_to_continue().ask()


def flow_status():
    """ステータス表示フロー"""
    project_dir = Path.cwd()
    console.print()
    show_status(project_dir)
    console.print()
    questionary.press_any_key_to_continue().ask()


def flow_clean():
    """クリーンアップフロー"""
    import shutil

    project_dir = Path.cwd()
    airlock_path = _get_airlock_path(project_dir)
    mappings_path = _get_mappings_path(project_dir)

    console.print("\n[yellow]警告: 以下を削除します[/yellow]")
    if airlock_path.exists():
        console.print(f"  - {airlock_path}")
    if mappings_path.exists():
        console.print(f"  - {mappings_path}")

    confirm = questionary.confirm(
        "本当に削除しますか？",
        default=False,
        style=custom_style,
    ).ask()

    if confirm:
        if airlock_path.exists():
            shutil.rmtree(airlock_path)
        if mappings_path.exists():
            shutil.rmtree(mappings_path)
        console.print("[green]✓ ワークスペースを削除しました[/green]")

    questionary.press_any_key_to_continue().ask()


def show_help():
    """ヘルプ表示"""
    console.print()
    console.print(Panel(
        "[bold]DataAirlock の使い方[/bold]\n\n"
        "1. [cyan]新しいプロジェクトを開始[/cyan]\n"
        "   → CSVファイルを選択し、個人情報を匿名化\n\n"
        "2. [cyan]Claude Code を起動[/cyan]\n"
        "   → 匿名化されたデータで分析作業\n\n"
        "3. [cyan]結果を復元[/cyan]\n"
        "   → PERSON_001 などを元の名前に戻す\n\n"
        "[dim]詳細: https://github.com/akira0907/dataairlock[/dim]",
        title="❓ ヘルプ",
    ))
    questionary.press_any_key_to_continue().ask()


def run_tui():
    """TUIメインループ"""
    try:
        while True:
            choice = main_menu()

            if choice is None or choice == "🚪 終了":
                console.print("\n[cyan]終了します[/cyan]")
                break
            elif choice == "📁 新しいプロジェクトを開始" or choice == "📁 ファイルを追加":
                flow_new_project()
            elif choice == "🚀 Claude Code を起動":
                flow_launch_claude()
            elif choice == "🔓 結果を復元":
                flow_restore()
            elif choice == "📋 ステータス確認":
                flow_status()
            elif choice == "🗑️ ワークスペースを削除":
                flow_clean()
            elif choice == "❓ ヘルプ":
                show_help()
    except KeyboardInterrupt:
        console.print("\n[cyan]終了します[/cyan]")


if __name__ == "__main__":
    run_tui()
