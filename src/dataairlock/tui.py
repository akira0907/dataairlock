"""DataAirlock 完全対話型TUI"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

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
    generate_session_id,
    load_mapping,
    save_mapping,
)
from dataairlock.folder_scanner import (
    ScannedFile,
    scan_folder,
    format_size,
    count_by_type,
    total_size,
    relative_to_mapping_name,
    SUPPORTED_EXTENSIONS as FOLDER_EXTENSIONS,
    CSV_EXTENSIONS,
    DOCUMENT_EXTENSIONS,
)
from dataairlock.profile import (
    Profile,
    ProfileManager,
    create_profile_from_actions,
    pii_type_to_profile_key,
)
from dataairlock.hybrid_detector import (
    HybridPIIDetector,
    DetectionMode,
    OllamaSetupStatus,
    check_ollama_status,
    setup_ollama_interactive,
)
from dataairlock.llm_client import (
    is_ollama_installed,
    is_ollama_running,
    get_ollama_install_instructions,
    start_ollama_server,
    pull_model,
    get_available_models,
)

console = Console()

# ワークスペース設定（cli.pyと共通）
AIRLOCK_DIR = ".airlock"
AIRLOCK_DATA_DIR = "data"
AIRLOCK_MAPPINGS_DIR = ".airlock_mappings"
AIRLOCK_OUTPUT_DIR = "output"
AIRLOCK_CONFIG = "airlock.json"
SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".xls"}

# 対応AIツール設定
AI_TOOLS = {
    "claude": {
        "name": "Claude Code",
        "command": "claude",
        "description": "Anthropic Claude Code CLI",
        "install_url": "https://claude.ai/code",
    },
    "vscode": {
        "name": "VS Code",
        "command": "code",
        "description": "Visual Studio Code で作業ディレクトリを開く",
        "install_url": "https://code.visualstudio.com",
        "open_mode": True,  # ディレクトリを開くモード
    },
    "codex": {
        "name": "OpenAI Codex CLI",
        "command": "codex",
        "description": "OpenAI Codex CLI",
        "install_url": "https://github.com/openai/codex",
    },
    "aider": {
        "name": "Aider",
        "command": "aider",
        "description": "AI pair programming in terminal",
        "install_url": "https://aider.chat",
    },
    "custom": {
        "name": "カスタムコマンド",
        "command": None,  # ユーザーが指定
        "description": "任意のコマンドを実行",
        "install_url": None,
    },
}

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


def select_file() -> Path | None:
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


def get_password(confirm: bool = True) -> str | None:
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


def check_ai_tool_available(tool_key: str) -> bool:
    """AIツールが利用可能かチェック"""
    tool = AI_TOOLS.get(tool_key)
    if not tool or tool_key == "custom":
        return tool_key == "custom"

    command = tool["command"]
    if not command:
        return False

    try:
        subprocess.run(
            [command, "--version"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_available_ai_tools() -> list[str]:
    """利用可能なAIツールのリストを取得"""
    available = []
    for key in AI_TOOLS:
        if key == "custom" or check_ai_tool_available(key):
            available.append(key)
    return available


def select_ai_tool() -> tuple[str, str | None]:
    """
    AIツールを選択

    Returns:
        (tool_key, custom_command)
        custom_command は tool_key == "custom" の場合のみ設定
    """
    available_tools = get_available_ai_tools()

    choices = []
    for key in ["claude", "vscode", "codex", "aider", "custom"]:
        tool = AI_TOOLS[key]
        if key in available_tools and key != "custom":
            choices.append(f"✅ {tool['name']} ({tool['command']})")
        elif key == "custom":
            choices.append(f"⚙️ {tool['name']}")
        else:
            choices.append(f"❌ {tool['name']} (未インストール)")

    choice = questionary.select(
        "使用するAIツールを選択:",
        choices=choices,
        style=custom_style,
    ).ask()

    if choice is None:
        return ("", None)

    # 選択からツールキーを特定
    for key in AI_TOOLS:
        tool = AI_TOOLS[key]
        if tool["name"] in choice:
            if key == "custom":
                custom_cmd = questionary.text(
                    "実行するコマンドを入力:",
                    style=custom_style,
                ).ask()
                if not custom_cmd:
                    return ("", None)
                return ("custom", custom_cmd.strip())
            elif "未インストール" in choice:
                console.print(f"[yellow]{tool['name']} がインストールされていません[/yellow]")
                if tool.get("install_url"):
                    console.print(f"[dim]インストール: {tool['install_url']}[/dim]")
                return ("", None)
            return (key, None)

    return ("", None)


def launch_ai_tool(
    airlock_path: Path,
    tool_key: str = "claude",
    custom_command: str | None = None,
) -> int:
    """
    AIツールを起動

    Args:
        airlock_path: 作業ディレクトリ
        tool_key: AI_TOOLSのキー
        custom_command: カスタムコマンド（tool_key="custom"の場合）

    Returns:
        終了コード
    """
    tool = AI_TOOLS.get(tool_key, AI_TOOLS["claude"])
    command = custom_command if tool_key == "custom" else tool["command"]
    tool_name = custom_command if tool_key == "custom" else tool["name"]

    console.print()
    console.print(f"[bold]🚀 {tool_name} を起動しています...[/bold]")
    console.print(f"   作業ディレクトリ: {airlock_path}")
    console.print()
    console.print("[dim]💡 ヒント: 作業が終わったら終了してください[/dim]")
    console.print()

    # 環境変数を設定
    env = os.environ.copy()
    env["DATAAIRLOCK_WORKSPACE"] = str(airlock_path)
    env["DATAAIRLOCK_DATA"] = str(airlock_path / "data")
    env["DATAAIRLOCK_OUTPUT"] = str(airlock_path / "output")

    # AIツールを起動
    try:
        # コマンドをシェル経由で実行（カスタムコマンド対応）
        if tool_key == "custom":
            result = subprocess.run(
                custom_command,
                cwd=str(airlock_path),
                env=env,
                shell=True,
            )
        elif tool.get("open_mode"):
            # VS Code等、ディレクトリを開くモード
            # --wait オプションでウィンドウが閉じるまで待機
            console.print("[dim]💡 VS Code を閉じると TUI に戻ります[/dim]")
            console.print()
            result = subprocess.run(
                [command, "--wait", str(airlock_path)],
                env=env,
            )
        else:
            result = subprocess.run(
                [command],
                cwd=str(airlock_path),
                env=env,
            )
        return result.returncode
    except FileNotFoundError:
        console.print(f"[red]エラー: {command} コマンドが見つかりません[/red]")
        if tool.get("install_url"):
            console.print(f"[dim]インストール: {tool['install_url']}[/dim]")
        return 1


def launch_claude_code(airlock_path: Path) -> int:
    """Claude Code を起動（互換性のため維持）"""
    return launch_ai_tool(airlock_path, "claude")


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


def _generate_mapping_report(mappings: dict, output_path: Path, title: str = "DataAirlock マッピングレポート") -> None:
    """
    マッピングレポートを生成

    Args:
        mappings: マッピング辞書
        output_path: 出力ファイルパス
        title: レポートのタイトル
    """
    lines = [
        "=" * 60,
        title,
        f"生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
        "このファイルには匿名化IDと元の値の対応表が含まれています。",
        "⚠️ 機密情報が含まれるため、取り扱いに注意してください。",
        "",
    ]

    # 各列のマッピングを出力
    for col_name, col_info in mappings.items():
        if col_name == "metadata":
            continue

        if not isinstance(col_info, dict):
            continue

        lines.append("-" * 60)
        lines.append(f"列: {col_name}")

        # PIIタイプ
        if "pii_type" in col_info:
            lines.append(f"タイプ: {col_info['pii_type']}")

        # マッピング一覧
        if "mapping" in col_info and isinstance(col_info["mapping"], dict):
            lines.append("")
            lines.append("マッピング:")
            for original, anonymized in col_info["mapping"].items():
                lines.append(f"  {anonymized} → {original}")

        lines.append("")

    # ファイル書き込み
    output_path.write_text("\n".join(lines), encoding="utf-8")


def _generate_anonymization_report(
    project_dir: Path,
    all_file_mappings: list[dict],
    password: str,
) -> Path:
    """
    匿名化時にマッピングレポートを生成（プロジェクトルートに配置）

    Args:
        project_dir: プロジェクトディレクトリ
        all_file_mappings: 各ファイルのマッピングリスト
        password: パスワード（マッピングファイル読み込み用）

    Returns:
        生成したレポートのパス
    """
    lines = [
        "=" * 70,
        "DataAirlock 匿名化マッピングレポート",
        f"生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70,
        "",
        "このファイルには匿名化IDと元の値の対応表が含まれています。",
        "AIツールに指示を出すとき、匿名化IDを使って具体的な指示ができます。",
        "",
        "例: 「PERSON_001 の来院回数を集計してください」",
        "",
        "⚠️ このファイルは機密情報を含むため、.gitignore に追加することを推奨します。",
        "",
    ]

    # 各ファイルのマッピングを統合して出力
    seen_mappings: dict[str, dict] = {}  # col_name -> {anonymized -> original}

    for file_mapping in all_file_mappings:
        for col_name, col_info in file_mapping.items():
            if col_name == "metadata":
                continue

            if not isinstance(col_info, dict):
                continue

            if col_name not in seen_mappings:
                seen_mappings[col_name] = {
                    "pii_type": col_info.get("pii_type", "不明"),
                    "mapping": {},
                }

            # valuesマッピングを追加（CSV/Excelファイル用）
            if "values" in col_info and isinstance(col_info["values"], dict):
                for original, anonymized in col_info["values"].items():
                    seen_mappings[col_name]["mapping"][anonymized] = original

    # マッピングを出力
    for col_name, info in seen_mappings.items():
        if not info.get("mapping"):
            continue

        lines.append("-" * 70)
        lines.append(f"【{col_name}】 ({info.get('pii_type', '不明')})")
        lines.append("")

        for anonymized, original in sorted(info["mapping"].items()):
            lines.append(f"  {anonymized:30} → {original}")

        lines.append("")

    # ファイルがない場合
    if not seen_mappings:
        lines.append("(匿名化されたデータはありません)")
        lines.append("")

    # ファイル書き込み（プロジェクトルートに配置）
    report_path = project_dir / "_MAPPING_REPORT.txt"
    report_path.write_text("\n".join(lines), encoding="utf-8")

    return report_path


# =============================================================================
# メインメニュー
# =============================================================================

def main_menu() -> str | None:
    """メインメニュー"""
    clear_screen()
    show_header()

    # カレントディレクトリにワークスペースがあるかチェック
    project_dir = Path.cwd()
    has_workspace = (_get_airlock_path(project_dir)).exists()

    if has_workspace:
        choices = [
            "🚀 AIツールを起動",
            "📂 フォルダを追加",
            "📁 ファイルを追加",
            "🔓 結果を復元",
            "📋 ステータス確認",
            "🗑️ ワークスペースを削除",
            "🚪 終了",
        ]
    else:
        choices = [
            "📂 フォルダから開始（推奨）",
            "📄 ファイルから開始",
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

    # マッピングレポート生成（プロジェクトルートに配置）
    report_path = _generate_anonymization_report(project_dir, [full_mapping], password)
    console.print(f"  [dim]📋 マッピングレポート: {report_path.name}[/dim]")

    console.print()
    console.print(Panel(
        "[green]✅ ワークスペース作成完了！[/green]",
        title="🔒",
    ))

    # 次のアクション
    next_action = questionary.select(
        "次のアクションは？",
        choices=[
            "🚀 AIツールを起動",
            "🔙 メニューに戻る",
        ],
        style=custom_style,
    ).ask()

    if next_action == "🚀 AIツールを起動":
        flow_launch_ai_tool(password)


def flow_launch_claude(password: str | None = None):
    """Claude Code起動フロー（互換性のため維持）"""
    flow_launch_ai_tool(password, tool_key="claude")


def flow_launch_ai_tool(password: str | None = None, tool_key: str = "", custom_command: str | None = None):
    """AIツール起動フロー"""
    project_dir = Path.cwd()
    airlock_path = _get_airlock_path(project_dir)

    if not airlock_path.exists():
        console.print("[red]ワークスペースがありません[/red]")
        return

    # ツールが指定されていない場合は選択
    if not tool_key:
        tool_key, custom_command = select_ai_tool()
        if not tool_key:
            return

    # AIツール起動
    exit_code = launch_ai_tool(airlock_path, tool_key, custom_command)

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
        "1. [cyan]フォルダから開始（推奨）[/cyan]\n"
        "   → フォルダを選択し、複数ファイルを一括匿名化\n\n"
        "2. [cyan]ファイルから開始[/cyan]\n"
        "   → 単一ファイルを選択し、個人情報を匿名化\n\n"
        "3. [cyan]AIツールを起動[/cyan]\n"
        "   → Claude Code / Codex CLI / Aider などで分析\n\n"
        "4. [cyan]結果を復元[/cyan]\n"
        "   → PERSON_001 などを元の名前に戻す\n\n"
        "[dim]詳細: https://github.com/akira0907/dataairlock[/dim]",
        title="❓ ヘルプ",
    ))
    questionary.press_any_key_to_continue().ask()


def prompt_ollama_setup(required_model: str = "llama3.1:8b") -> bool:
    """
    Ollamaセットアップを対話的に行う

    Returns:
        セットアップ成功/LLM使用可能ならTrue
    """
    status = check_ollama_status(required_model)

    if status == OllamaSetupStatus.READY:
        return True

    if status == OllamaSetupStatus.NOT_INSTALLED:
        console.print("\n[yellow]⚠️ Ollamaがインストールされていません[/yellow]")
        console.print(f"[dim]{get_ollama_install_instructions()}[/dim]")

        choice = questionary.select(
            "Ollamaを使用しますか？",
            choices=[
                "⏭️ LLMなしで続行（ルールベース検出のみ）",
                "📖 インストール手順を表示",
                "❌ キャンセル",
            ],
            style=custom_style,
        ).ask()

        if choice is None or "キャンセル" in choice:
            return False
        if "インストール手順" in choice:
            console.print(f"\n[bold]Ollamaインストール方法:[/bold]")
            console.print(f"  {get_ollama_install_instructions()}")
            console.print("\n[dim]インストール後に再度実行してください[/dim]")
            questionary.press_any_key_to_continue().ask()
        return False

    if status == OllamaSetupStatus.NOT_RUNNING:
        console.print("\n[yellow]⚠️ Ollamaサーバーが起動していません[/yellow]")

        choice = questionary.select(
            "どうしますか？",
            choices=[
                "🚀 Ollamaサーバーを起動",
                "⏭️ LLMなしで続行（ルールベース検出のみ）",
                "❌ キャンセル",
            ],
            style=custom_style,
        ).ask()

        if choice is None or "キャンセル" in choice:
            return False
        if "LLMなし" in choice:
            return False
        if "起動" in choice:
            console.print("[dim]Ollamaサーバーを起動中...[/dim]")
            if start_ollama_server():
                console.print("[green]✓ Ollamaサーバーを起動しました[/green]")
                # モデルチェックへ
                status = check_ollama_status(required_model)
                if status == OllamaSetupStatus.READY:
                    return True
            else:
                console.print("[red]サーバーの起動に失敗しました[/red]")
                console.print("[dim]手動で 'ollama serve' を実行してください[/dim]")
                return False

    if status == OllamaSetupStatus.NO_MODEL:
        console.print(f"\n[yellow]⚠️ モデル '{required_model}' がありません[/yellow]")
        available = get_available_models()
        if available:
            console.print(f"[dim]利用可能なモデル: {', '.join(available[:5])}[/dim]")

        choice = questionary.select(
            "どうしますか？",
            choices=[
                f"📥 モデルをダウンロード ({required_model})",
                "⏭️ LLMなしで続行（ルールベース検出のみ）",
                "❌ キャンセル",
            ],
            style=custom_style,
        ).ask()

        if choice is None or "キャンセル" in choice:
            return False
        if "LLMなし" in choice:
            return False
        if "ダウンロード" in choice:
            console.print(f"[dim]モデル '{required_model}' をダウンロード中...[/dim]")
            console.print("[dim]（初回は数GB、数分かかる場合があります）[/dim]")
            if pull_model(required_model):
                console.print(f"[green]✓ モデル '{required_model}' をダウンロードしました[/green]")
                return True
            else:
                console.print("[red]モデルのダウンロードに失敗しました[/red]")
                return False

    return False


def select_detection_mode() -> DetectionMode | None:
    """
    PII検出モードを選択

    Returns:
        選択されたDetectionMode、またはNone（キャンセル）
    """
    # Ollamaが使える状態かチェック
    ollama_available = check_ollama_status() == OllamaSetupStatus.READY

    if ollama_available:
        choices = [
            "🔄 ハイブリッド（ルール + LLM）← おすすめ",
            "📏 ルールベースのみ（高速）",
            "🤖 LLMのみ（精度重視）",
        ]
    else:
        choices = [
            "📏 ルールベースのみ（高速）",
            "🔧 LLMを設定して使用",
        ]

    choice = questionary.select(
        "PII検出モードを選択:",
        choices=choices,
        style=custom_style,
    ).ask()

    if choice is None:
        return None

    if "ハイブリッド" in choice:
        return DetectionMode.HYBRID
    elif "LLMのみ" in choice:
        return DetectionMode.LLM_ONLY
    elif "ルールベース" in choice:
        return DetectionMode.RULE_ONLY
    elif "LLMを設定" in choice:
        # Ollamaセットアップを実行
        if prompt_ollama_setup():
            # セットアップ成功したらモード選択に戻る
            return select_detection_mode()
        return DetectionMode.RULE_ONLY

    return DetectionMode.RULE_ONLY


def detect_common_columns(
    files: list[ScannedFile],
    detection_mode: DetectionMode = DetectionMode.RULE_ONLY,
) -> dict[str, dict]:
    """
    複数ファイルから共通のPII列を検出

    Args:
        files: スキャンされたファイルリスト
        detection_mode: 検出モード（RULE_ONLY, LLM_ONLY, HYBRID）

    Returns:
        列名→{pii_type, file_count, sample_values}のマッピング
    """
    from collections import defaultdict

    all_columns: dict[str, dict] = defaultdict(lambda: {
        "pii_type": None,
        "files": [],
        "sample_values": [],
        "detected_by": None,
    })

    csv_files = [f for f in files if f.extension in CSV_EXTENSIONS]

    # ハイブリッド検出器を使用
    if detection_mode != DetectionMode.RULE_ONLY:
        detector = HybridPIIDetector(mode=detection_mode)
    else:
        detector = None

    for scanned_file in csv_files:
        try:
            df = load_dataframe(scanned_file.path)

            if detector and detection_mode != DetectionMode.RULE_ONLY:
                # ハイブリッド/LLM検出
                hybrid_results = detector.detect_pii_columns(df)
                pii_columns = detector.to_pii_column_results(hybrid_results)

                for col_name, result in pii_columns.items():
                    all_columns[col_name]["pii_type"] = result.pii_type
                    all_columns[col_name]["files"].append(str(scanned_file.relative_path))
                    all_columns[col_name]["detected_by"] = result.matched_by
                    # サンプル値を追加（重複除去）
                    for sample in result.sample_values[:2]:
                        if sample not in all_columns[col_name]["sample_values"]:
                            all_columns[col_name]["sample_values"].append(sample)
                            if len(all_columns[col_name]["sample_values"]) >= 3:
                                break
            else:
                # ルールベース検出のみ
                pii_columns = detect_pii_columns(df)

                for col_name, result in pii_columns.items():
                    all_columns[col_name]["pii_type"] = result.pii_type
                    all_columns[col_name]["files"].append(str(scanned_file.relative_path))
                    all_columns[col_name]["detected_by"] = "rule"
                    # サンプル値を追加（重複除去）
                    for sample in result.sample_values[:2]:
                        if sample not in all_columns[col_name]["sample_values"]:
                            all_columns[col_name]["sample_values"].append(sample)
                            if len(all_columns[col_name]["sample_values"]) >= 3:
                                break
        except Exception:
            pass

    return dict(all_columns)


def select_profile_mode() -> str | None:
    """
    プロファイル使用モードを選択

    Returns:
        "use_existing": 既存プロファイルを使用
        "new": 新規に設定（プロファイル保存可）
        "once": 今回のみ設定（保存しない）
        None: キャンセル
    """
    choice = questionary.select(
        "プロファイルを使用しますか？",
        choices=[
            "📋 既存のプロファイルを使用",
            "✨ 新規に設定（プロファイル保存可）",
            "⏭️ 今回のみ設定（保存しない）",
        ],
        style=custom_style,
    ).ask()

    if choice is None:
        return None

    if "既存" in choice:
        return "use_existing"
    elif "新規" in choice:
        return "new"
    else:
        return "once"


def select_existing_profile(manager: ProfileManager) -> Profile | None:
    """
    既存プロファイルを選択

    Args:
        manager: ProfileManager インスタンス

    Returns:
        選択されたプロファイル、または None（キャンセル）
    """
    profiles = manager.list_profiles()

    if not profiles:
        console.print("[yellow]保存されたプロファイルがありません[/yellow]")
        return None

    choices = []
    for p in profiles:
        last_used = ""
        if p.last_used_at:
            last_used = f" (最終使用: {p.last_used_at.strftime('%Y-%m-%d')})"
        elif p.updated_at:
            last_used = f" (更新: {p.updated_at.strftime('%Y-%m-%d')})"
        choices.append(f"{p.name}{last_used}")

    choices.append("← 戻る")

    choice = questionary.select(
        "プロファイルを選択:",
        choices=choices,
        style=custom_style,
    ).ask()

    if choice is None or "戻る" in choice:
        return None

    # 選択されたプロファイルを取得
    selected_name = choice.split(" (")[0]
    for p in profiles:
        if p.name == selected_name:
            return p

    return None


def apply_profile_to_columns(
    profile: Profile,
    common_columns: dict[str, dict],
) -> tuple[dict[str, str], list[str]]:
    """
    プロファイルを列に適用

    Args:
        profile: 適用するプロファイル
        common_columns: 検出されたPII列

    Returns:
        (column_actions, unmatched_columns)
        column_actions: 列名→アクション のマッピング
        unmatched_columns: マッチしなかった列名のリスト
    """
    column_actions = {}
    unmatched_columns = []

    for col_name, info in common_columns.items():
        pii_type = info["pii_type"]
        pii_key = pii_type_to_profile_key(pii_type.value) if pii_type else None

        action = profile.get_action_for_column(col_name, pii_key)
        if action:
            column_actions[col_name] = action
        else:
            unmatched_columns.append(col_name)

    return column_actions, unmatched_columns


def offer_save_profile(
    column_actions: dict[str, str],
    common_columns: dict[str, dict],
    manager: ProfileManager,
) -> None:
    """
    プロファイル保存を提案

    Args:
        column_actions: 列名→アクション のマッピング
        common_columns: 検出されたPII列情報
        manager: ProfileManager インスタンス
    """
    choice = questionary.select(
        "この設定をプロファイルとして保存しますか？",
        choices=[
            "💾 新規プロファイルとして保存",
            "📝 既存プロファイルを更新",
            "⏭️ 保存しない",
        ],
        style=custom_style,
    ).ask()

    if choice is None or "保存しない" in choice:
        return

    # 列名とPIIタイプの対応を作成
    column_pii_types = {}
    for col_name, action in column_actions.items():
        if col_name in common_columns:
            pii_type = common_columns[col_name]["pii_type"]
            pii_key = pii_type_to_profile_key(pii_type.value) if pii_type else "unknown"
        else:
            pii_key = "unknown"
        column_pii_types[col_name] = (pii_key, action)

    if "新規" in choice:
        # 新規プロファイル作成
        name = questionary.text(
            "プロファイル名:",
            style=custom_style,
        ).ask()

        if not name:
            return

        profile = create_profile_from_actions(name, column_pii_types)
        path = manager.save(profile)
        console.print(f"[green]✓ プロファイルを保存しました: {path}[/green]")

    elif "更新" in choice:
        # 既存プロファイルを更新
        profiles = manager.list_profiles()
        if not profiles:
            console.print("[yellow]保存されたプロファイルがありません[/yellow]")
            return

        profile_choices = [p.name for p in profiles]
        profile_choices.append("← キャンセル")

        selected = questionary.select(
            "更新するプロファイル:",
            choices=profile_choices,
            style=custom_style,
        ).ask()

        if selected is None or "キャンセル" in selected:
            return

        profile = manager.load(selected)
        if profile:
            # 既存の設定を更新
            for col_name, (pii_key, action) in column_pii_types.items():
                profile.update_column_rule(col_name, action)
                if pii_key:
                    profile.update_pii_type_default(pii_key, action)
            manager.save(profile)
            console.print(f"[green]✓ プロファイル「{selected}」を更新しました[/green]")


def generate_airlock_docs(airlock_path: Path, files: list, session_id: str = "") -> None:
    """
    .airlock ディレクトリにドキュメントを生成

    Args:
        airlock_path: .airlockディレクトリのパス
        files: 処理されたファイルリスト
        session_id: セッションID（オプション）
    """
    # ファイルリスト
    file_list = "\n".join([f"- `data/{f.relative_path}`" for f in files[:20]])
    if len(files) > 20:
        file_list += f"\n- ... 他 {len(files) - 20} ファイル"

    file_list_plain = "\n".join([f"- data/{f.relative_path}" for f in files[:20]])
    if len(files) > 20:
        file_list_plain += f"\n- ... 他 {len(files) - 20} ファイル"

    # README.md（汎用・全ツール向け）
    readme_content = f"""# DataAirlock Workspace

このディレクトリはDataAirlockによって生成された**セキュアな作業環境**です。
個人情報は匿名化されており、安全にAIツールで分析できます。

## ディレクトリ構造

```
.airlock/
├── data/           # 匿名化済みデータ（AIに渡してOK）
├── output/         # 分析結果の出力先
├── CLAUDE.md       # Claude Code用設定
├── SYSTEM_PROMPT.md # 汎用システムプロンプト
├── PROMPT.md       # 分析依頼テンプレート
└── README.md       # このファイル
```

## 利用可能なファイル

{file_list}

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
3. **復元**: プロジェクトルートで `dataairlock` を実行し「結果を復元」を選択

## 注意事項

- 復元用マッピングは `../{AIRLOCK_MAPPINGS_DIR}/` に保存されています（Git除外済み）
- このディレクトリ外のファイルにはアクセスしないでください

生成日時: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

    # CLAUDE.md（Claude Code用）
    claude_content = f"""# DataAirlock セキュア環境

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

## 利用可能なファイル

{file_list}

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

    # SYSTEM_PROMPT.md（汎用LLMツール用）
    system_prompt_content = f"""あなたはDataAirlockセキュア環境内で作業するAIアシスタントです。

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

# 利用可能なファイル

{file_list_plain}

# 作業手順

1. data/ 内のファイルを読み込む
2. 分析・処理を行う
3. 結果を output/ に保存する

匿名化IDの復元は別途行われるため、あなたが行う必要はありません。
"""

    # PROMPT.md（分析依頼テンプレート）
    prompt_content = f"""# 分析依頼

## 対象データ

以下のファイルが `data/` ディレクトリにあります:

{file_list}

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

    # ファイル書き込み
    readme_path = airlock_path / "README.md"
    claude_path = airlock_path / "CLAUDE.md"
    system_prompt_path = airlock_path / "SYSTEM_PROMPT.md"
    prompt_path = airlock_path / "PROMPT.md"

    readme_path.write_text(readme_content, encoding="utf-8")
    claude_path.write_text(claude_content, encoding="utf-8")
    system_prompt_path.write_text(system_prompt_content, encoding="utf-8")
    prompt_path.write_text(prompt_content, encoding="utf-8")


def select_folder() -> Path | None:
    """フォルダ選択（カレントディレクトリがデフォルト）"""
    current_dir = str(Path.cwd())

    folder_path = questionary.path(
        "フォルダを選択（パスを入力、またはドラッグ＆ドロップ）:",
        default=current_dir,
        only_directories=True,
        style=custom_style,
    ).ask()

    if not folder_path:
        return None

    path = Path(folder_path.strip().strip("'\""))
    if not path.exists():
        console.print(f"[red]エラー: フォルダが見つかりません: {path}[/red]")
        return None

    if not path.is_dir():
        console.print(f"[red]エラー: ディレクトリではありません: {path}[/red]")
        return None

    return path


def flow_folder_project():
    """フォルダベースのプロジェクトフロー"""
    project_dir = Path.cwd()

    # フォルダ選択
    console.print("\n[bold]📂 フォルダを選択[/bold]")
    console.print("[dim]CSV/Excel/Word/PowerPointファイルを自動検出します[/dim]\n")

    folder_path = select_folder()
    if not folder_path:
        return

    # 再帰オプション
    recursive = questionary.confirm(
        "サブフォルダも含めますか？",
        default=True,
        style=custom_style,
    ).ask()

    if recursive is None:
        return

    # スキャン実行
    console.print("\n[bold]🔍 スキャン中...[/bold]")
    files = scan_folder(folder_path, recursive=recursive)

    if not files:
        console.print("[yellow]対象ファイルが見つかりませんでした[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    # 結果表示
    type_counts = count_by_type(files)
    total = total_size(files)

    console.print(f"\n[green]✓ {len(files)}ファイルを検出[/green]")
    for type_name, count in sorted(type_counts.items()):
        console.print(f"  {type_name}: {count}件")
    console.print(f"  合計サイズ: {format_size(total)}")

    # ファイル一覧表示
    show_files = questionary.confirm(
        "ファイル一覧を表示しますか？",
        default=False,
        style=custom_style,
    ).ask()

    if show_files:
        table = Table(title="検出ファイル", show_header=True)
        table.add_column("パス")
        table.add_column("タイプ")
        table.add_column("サイズ")

        for f in files[:20]:
            table.add_row(
                str(f.relative_path),
                f.file_type_name,
                format_size(f.size),
            )

        if len(files) > 20:
            table.add_row("...", f"(他 {len(files) - 20}件)", "")

        console.print(table)

    # CSVファイルのPII検出
    csv_files = [f for f in files if f.is_csv]
    doc_files = [f for f in files if f.is_document]

    if not csv_files and not doc_files:
        console.print("[yellow]処理可能なファイルがありません[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    # PII検出（CSVファイルのみ）
    profile_manager = ProfileManager()
    profile_mode = None  # プロファイルモード追跡用
    used_profile = None  # 使用したプロファイル
    detection_mode = DetectionMode.RULE_ONLY  # デフォルト

    if csv_files:
        # 検出モード選択（オプション）
        use_llm = questionary.confirm(
            "LLMを使用してPII検出の精度を向上させますか？",
            default=False,
            style=custom_style,
        ).ask()

        if use_llm:
            detection_mode = select_detection_mode()
            if detection_mode is None:
                return

        console.print(f"\n[bold]🔍 PII検出中... ({len(csv_files)}ファイル)[/bold]")
        if detection_mode != DetectionMode.RULE_ONLY:
            console.print(f"[dim]検出モード: {detection_mode.value}[/dim]")

        common_columns = detect_common_columns(csv_files, detection_mode)

        if common_columns:
            console.print(f"[yellow]⚠️ {len(common_columns)}件の個人情報列を検出[/yellow]")

            # プロファイル使用の確認
            profile_mode = select_profile_mode()
            if profile_mode is None:
                return

            column_actions = {}

            if profile_mode == "use_existing":
                # 既存プロファイルを使用
                profile = select_existing_profile(profile_manager)
                if profile is None:
                    # プロファイル選択がキャンセルされた場合、手動モードにフォールバック
                    profile_mode = "once"
                else:
                    used_profile = profile
                    profile.mark_used()
                    profile_manager.save(profile)

                    # プロファイルを適用
                    column_actions, unmatched = apply_profile_to_columns(profile, common_columns)

                    if column_actions:
                        console.print(f"\n[green]✓ プロファイル「{profile.name}」を適用しました[/green]")
                        for col_name, action in column_actions.items():
                            action_label = {"replace": "置換", "generalize": "一般化", "delete": "削除", "skip": "スキップ"}
                            console.print(f"   {col_name}: {action_label.get(action, action)}")

                    # マッチしなかった列は手動で設定
                    if unmatched:
                        console.print(f"\n[yellow]⚠️ {len(unmatched)}件の列がプロファイルにマッチしませんでした[/yellow]")
                        for col_name in unmatched:
                            info = common_columns[col_name]
                            pii_type = info["pii_type"]
                            samples = ", ".join(info["sample_values"][:2]) if info["sample_values"] else "N/A"

                            console.print(f"\n[yellow]⚠️[/yellow] [cyan]{col_name}[/cyan] ({pii_type.value})")
                            console.print(f"   サンプル: {samples}")

                            default_choice = "🔄 置換（PERSON_001形式）← おすすめ"
                            if pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
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
                                return

                            action_map = {
                                "🔄 置換（PERSON_001形式）← おすすめ": "replace",
                                "📊 一般化（年代・都道府県等）": "generalize",
                                "🗑️ 削除": "delete",
                                "⏭️ スキップ（処理しない）": "skip",
                            }
                            column_actions[col_name] = action_map[choice]

            # 手動モード（new または once、またはプロファイル選択キャンセル時）
            if profile_mode in ["new", "once"] or (profile_mode == "use_existing" and used_profile is None):
                for col_name, info in common_columns.items():
                    pii_type = info["pii_type"]
                    file_count = len(info["files"])
                    samples = ", ".join(info["sample_values"][:2]) if info["sample_values"] else "N/A"

                    console.print(f"\n[yellow]⚠️[/yellow] [cyan]{col_name}[/cyan] ({pii_type.value})")
                    console.print(f"   {file_count}ファイルで検出")
                    console.print(f"   サンプル: {samples}")

                    default_choice = "🔄 置換（PERSON_001形式）← おすすめ"
                    if pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
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
                        return

                    action_map = {
                        "🔄 置換（PERSON_001形式）← おすすめ": "replace",
                        "📊 一般化（年代・都道府県等）": "generalize",
                        "🗑️ 削除": "delete",
                        "⏭️ スキップ（処理しない）": "skip",
                    }
                    column_actions[col_name] = action_map[choice]
        else:
            console.print("[green]✓ CSVファイルにPIIは検出されませんでした[/green]")
            column_actions = {}
    else:
        column_actions = {}
        common_columns = {}

    # ドキュメントの処理方法
    doc_strategy = "replace"
    if doc_files:
        console.print(f"\n[bold]📝 ドキュメントファイル: {len(doc_files)}件[/bold]")
        doc_choice = questionary.select(
            "ドキュメント内のPII処理方法:",
            choices=[
                "🔄 置換（PHONE_001形式）← おすすめ",
                "📊 一般化",
                "⏭️ スキップ（処理しない）",
            ],
            style=custom_style,
        ).ask()

        if doc_choice is None:
            return

        if "スキップ" in doc_choice:
            doc_files = []
        elif "一般化" in doc_choice:
            doc_strategy = "generalize"

    # 処理対象がない場合
    columns_to_process = {k: v for k, v in column_actions.items() if v != "skip"}
    if not columns_to_process and not doc_files:
        console.print("[yellow]処理対象がありません[/yellow]")
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
    mappings_path = _get_mappings_path(project_dir)

    # ワークスペース全体で共通のセッションIDとマッピングを使用
    # これにより同じ値には同じ匿名化IDが割り当てられる
    workspace_session_id = generate_session_id()
    global_mapping: dict[str, dict[str, str]] = {}

    config = {
        "created_at": datetime.now().isoformat(),
        "source_directory": str(folder_path),
        "files": {},
        "folder_mode": True,
        "session_id": workspace_session_id,
    }

    processed_count = 0
    error_count = 0
    all_file_mappings: list[dict] = []  # マッピングレポート用

    # CSVファイルの処理
    for scanned_file in csv_files:
        try:
            df = load_dataframe(scanned_file.path)

            # 衝突チェック
            warnings = check_collision(df)
            for w in warnings:
                console.print(f"[yellow]{scanned_file.relative_path}: {w}[/yellow]")

            # このファイルにあるPII列のみ処理
            file_pii = detect_pii_columns(df)
            file_actions = {
                col: action
                for col, action in columns_to_process.items()
                if col in file_pii
            }

            # ファイル個別のマッピング
            file_mapping: dict = {
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "original_file": str(scanned_file.path),
                    "columns_processed": list(file_actions.keys()),
                    "session_id": workspace_session_id,
                }
            }

            if file_actions:
                anonymized_df = df.copy()
                for col_name, action in file_actions.items():
                    if col_name in file_pii:
                        single_col_pii = {col_name: file_pii[col_name]}
                        anonymized_df, col_mapping = anonymize_dataframe(
                            anonymized_df,
                            single_col_pii,
                            strategy=action,
                            session_id=workspace_session_id,
                            global_mapping=global_mapping,
                        )
                        # ファイル個別マッピングに追加
                        if col_name in col_mapping:
                            file_mapping[col_name] = col_mapping[col_name]
            else:
                anonymized_df = df

            # 出力（ディレクトリ構造を維持）
            output_path = airlock_path / "data" / scanned_file.relative_path.with_suffix(".csv")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            save_dataframe(anonymized_df, output_path)

            # マッピングファイル保存（ファイル個別）
            mapping_name = relative_to_mapping_name(scanned_file.relative_path)
            mapping_output = mappings_path / mapping_name
            save_mapping(file_mapping, mapping_output, password)

            # レポート用にマッピングを収集
            all_file_mappings.append(file_mapping)

            config["files"][str(scanned_file.relative_path)] = {
                "original": str(scanned_file.path),
                "anonymized": str(output_path.relative_to(airlock_path)),
                "mapping": mapping_name,
                "pii_columns": list(file_actions.keys()),
            }

            console.print(f"  [green]✓[/green] {scanned_file.relative_path}")
            processed_count += 1

        except Exception as e:
            console.print(f"  [red]✗[/red] {scanned_file.relative_path}: {e}")
            error_count += 1

    # ドキュメントファイルの処理
    if doc_files:
        from dataairlock.document_anonymizer import anonymize_document

        for scanned_file in doc_files:
            try:
                output_path = airlock_path / "data" / scanned_file.relative_path
                output_path.parent.mkdir(parents=True, exist_ok=True)

                result, doc_mapping = anonymize_document(
                    scanned_file.path,
                    output_path,
                    doc_strategy,
                )

                # ドキュメント個別マッピング
                doc_file_mapping: dict = {
                    "metadata": {
                        "created_at": datetime.now().isoformat(),
                        "original_file": str(scanned_file.path),
                        "type": "document",
                        "pii_count": result.total_matches,
                    }
                }
                if "values" in doc_mapping:
                    doc_file_mapping["values"] = doc_mapping["values"]

                # マッピングファイル保存（ファイル個別）
                mapping_name = relative_to_mapping_name(scanned_file.relative_path)
                mapping_output = mappings_path / mapping_name
                save_mapping(doc_file_mapping, mapping_output, password)

                # レポート用にマッピングを収集
                all_file_mappings.append(doc_file_mapping)

                config["files"][str(scanned_file.relative_path)] = {
                    "original": str(scanned_file.path),
                    "anonymized": str(output_path.relative_to(airlock_path)),
                    "mapping": mapping_name,
                    "type": "document",
                    "pii_count": result.total_matches,
                }

                console.print(f"  [green]✓[/green] {scanned_file.relative_path} ({result.total_matches}件のPII)")
                processed_count += 1

            except Exception as e:
                console.print(f"  [red]✗[/red] {scanned_file.relative_path}: {e}")
                error_count += 1

    # ドキュメント生成
    generate_airlock_docs(airlock_path, files)

    # マッピングレポート生成（プロジェクトルートに配置）
    if all_file_mappings:
        report_path = _generate_anonymization_report(project_dir, all_file_mappings, password)
        console.print(f"  [dim]📋 マッピングレポート: {report_path.name}[/dim]")

    # 設定保存
    _save_workspace_config(project_dir, config)

    console.print()
    console.print(Panel(
        f"[green]✅ {processed_count}ファイルを処理しました[/green]"
        + (f"\n[yellow]⚠️ {error_count}ファイルでエラー[/yellow]" if error_count else ""),
        title="🔒 完了",
    ))

    # プロファイル保存の提案（newモードの場合）
    if profile_mode == "new" and column_actions and common_columns:
        offer_save_profile(column_actions, common_columns, profile_manager)

    # 次のアクション
    next_action = questionary.select(
        "次のアクションは？",
        choices=[
            "🚀 AIツールを起動",
            "🔙 メニューに戻る",
        ],
        style=custom_style,
    ).ask()

    if next_action == "🚀 AIツールを起動":
        flow_launch_ai_tool(password)


def flow_add_folder():
    """既存ワークスペースにフォルダを追加"""
    project_dir = Path.cwd()
    airlock_path = _get_airlock_path(project_dir)
    mappings_path = _get_mappings_path(project_dir)

    if not airlock_path.exists():
        console.print("[red]ワークスペースがありません[/red]")
        return

    # フォルダ選択
    console.print("\n[bold]📂 追加するフォルダを選択[/bold]")
    console.print("[dim]CSV/Excel/Word/PowerPointファイルを自動検出します[/dim]\n")

    folder_path = select_folder()
    if not folder_path:
        return

    # 再帰オプション
    recursive = questionary.confirm(
        "サブフォルダも含めますか？",
        default=True,
        style=custom_style,
    ).ask()

    if recursive is None:
        return

    # スキャン実行
    console.print("\n[bold]🔍 スキャン中...[/bold]")
    files = scan_folder(folder_path, recursive=recursive)

    if not files:
        console.print("[yellow]対象ファイルが見つかりませんでした[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    # 結果表示
    type_counts = count_by_type(files)
    total = total_size(files)

    console.print(f"\n[green]✓ {len(files)}ファイルを検出[/green]")
    for type_name, count in sorted(type_counts.items()):
        console.print(f"  {type_name}: {count}件")
    console.print(f"  合計サイズ: {format_size(total)}")

    # CSVファイルのPII検出
    csv_files = [f for f in files if f.is_csv]
    doc_files = [f for f in files if f.is_document]

    if not csv_files and not doc_files:
        console.print("[yellow]処理可能なファイルがありません[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    # PII検出（CSVファイルのみ）
    profile_manager = ProfileManager()
    profile_mode = None
    used_profile = None
    detection_mode = DetectionMode.RULE_ONLY

    if csv_files:
        # 検出モード選択（オプション）
        use_llm = questionary.confirm(
            "LLMを使用してPII検出の精度を向上させますか？",
            default=False,
            style=custom_style,
        ).ask()

        if use_llm:
            detection_mode = select_detection_mode()
            if detection_mode is None:
                return

        console.print(f"\n[bold]🔍 PII検出中... ({len(csv_files)}ファイル)[/bold]")
        if detection_mode != DetectionMode.RULE_ONLY:
            console.print(f"[dim]検出モード: {detection_mode.value}[/dim]")

        common_columns = detect_common_columns(csv_files, detection_mode)

        if common_columns:
            console.print(f"[yellow]⚠️ {len(common_columns)}件の個人情報列を検出[/yellow]")

            # プロファイル使用の確認
            profile_mode = select_profile_mode()
            if profile_mode is None:
                return

            column_actions = {}

            if profile_mode == "use_existing":
                profile = select_existing_profile(profile_manager)
                if profile is None:
                    profile_mode = "once"
                else:
                    used_profile = profile
                    profile.mark_used()
                    profile_manager.save(profile)

                    column_actions, unmatched = apply_profile_to_columns(profile, common_columns)

                    if column_actions:
                        console.print(f"\n[green]✓ プロファイル「{profile.name}」を適用しました[/green]")
                        for col_name, action in column_actions.items():
                            action_label = {"replace": "置換", "generalize": "一般化", "delete": "削除", "skip": "スキップ"}
                            console.print(f"   {col_name}: {action_label.get(action, action)}")

                    if unmatched:
                        console.print(f"\n[yellow]⚠️ {len(unmatched)}件の列がプロファイルにマッチしませんでした[/yellow]")
                        for col_name in unmatched:
                            info = common_columns[col_name]
                            pii_type = info["pii_type"]
                            samples = ", ".join(info["sample_values"][:2]) if info["sample_values"] else "N/A"

                            console.print(f"\n[yellow]⚠️[/yellow] [cyan]{col_name}[/cyan] ({pii_type.value})")
                            console.print(f"   サンプル: {samples}")

                            default_choice = "🔄 置換（PERSON_001形式）← おすすめ"
                            if pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
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
                                return

                            action_map = {
                                "🔄 置換（PERSON_001形式）← おすすめ": "replace",
                                "📊 一般化（年代・都道府県等）": "generalize",
                                "🗑️ 削除": "delete",
                                "⏭️ スキップ（処理しない）": "skip",
                            }
                            column_actions[col_name] = action_map[choice]

            if profile_mode in ["new", "once"] or (profile_mode == "use_existing" and used_profile is None):
                for col_name, info in common_columns.items():
                    pii_type = info["pii_type"]
                    file_count = len(info["files"])
                    samples = ", ".join(info["sample_values"][:2]) if info["sample_values"] else "N/A"

                    console.print(f"\n[yellow]⚠️[/yellow] [cyan]{col_name}[/cyan] ({pii_type.value})")
                    console.print(f"   {file_count}ファイルで検出")
                    console.print(f"   サンプル: {samples}")

                    default_choice = "🔄 置換（PERSON_001形式）← おすすめ"
                    if pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
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
                        return

                    action_map = {
                        "🔄 置換（PERSON_001形式）← おすすめ": "replace",
                        "📊 一般化（年代・都道府県等）": "generalize",
                        "🗑️ 削除": "delete",
                        "⏭️ スキップ（処理しない）": "skip",
                    }
                    column_actions[col_name] = action_map[choice]
        else:
            console.print("[green]✓ CSVファイルにPIIは検出されませんでした[/green]")
            column_actions = {}
    else:
        column_actions = {}
        common_columns = {}

    # ドキュメントの処理方法
    doc_strategy = "replace"
    if doc_files:
        console.print(f"\n[bold]📝 ドキュメントファイル: {len(doc_files)}件[/bold]")
        doc_choice = questionary.select(
            "ドキュメント内のPII処理方法:",
            choices=[
                "🔄 置換（PHONE_001形式）← おすすめ",
                "📊 一般化",
                "⏭️ スキップ（処理しない）",
            ],
            style=custom_style,
        ).ask()

        if doc_choice is None:
            return

        if "スキップ" in doc_choice:
            doc_files = []
        elif "一般化" in doc_choice:
            doc_strategy = "generalize"

    # 処理対象がない場合
    columns_to_process = {k: v for k, v in column_actions.items() if v != "skip"}
    if not columns_to_process and not doc_files:
        console.print("[yellow]処理対象がありません[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    # パスワード入力
    console.print("\n[bold]🔐 パスワード設定[/bold]")
    password = get_password(confirm=True)
    if not password:
        return

    # 確認
    console.print("\n[bold]📋 処理内容の確認[/bold]")
    console.print(f"  フォルダ: {folder_path}")
    console.print(f"  ファイル数: {len(files)}")
    if columns_to_process:
        console.print(f"  処理列: {len(columns_to_process)}列")
    if doc_files:
        console.print(f"  ドキュメント: {len(doc_files)}件")

    confirm = questionary.confirm(
        "この内容で追加処理を実行しますか？",
        default=True,
        style=custom_style,
    ).ask()

    if not confirm:
        console.print("[yellow]キャンセルしました[/yellow]")
        return

    # 処理実行
    console.print("\n[bold]🔄 処理中...[/bold]")

    processed_count = 0
    error_count = 0
    all_file_mappings: list[dict] = []  # マッピングレポート用

    # 既存の設定を読み込み
    config = _load_workspace_config(project_dir) or {}
    if "files" not in config:
        config["files"] = {}

    # 既存のsession_idを使用するか、新規生成
    workspace_session_id = config.get("session_id") or generate_session_id()
    config["session_id"] = workspace_session_id
    global_mapping: dict[str, dict[str, str]] = {}

    # CSVファイルの処理
    for scanned_file in csv_files:
        try:
            df = load_dataframe(scanned_file.path)

            # 衝突チェック
            warnings = check_collision(df)
            for w in warnings:
                console.print(f"[yellow]{scanned_file.relative_path}: {w}[/yellow]")

            # このファイルにあるPII列のみ処理
            file_pii = detect_pii_columns(df)
            file_actions = {
                col: action
                for col, action in columns_to_process.items()
                if col in file_pii
            }

            # ファイル個別のマッピング
            file_mapping: dict = {
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "original_file": str(scanned_file.path),
                    "columns_processed": list(file_actions.keys()),
                    "session_id": workspace_session_id,
                }
            }

            if file_actions:
                anonymized_df = df.copy()
                for col_name, action in file_actions.items():
                    if col_name in file_pii:
                        single_col_pii = {col_name: file_pii[col_name]}
                        anonymized_df, col_mapping = anonymize_dataframe(
                            anonymized_df,
                            single_col_pii,
                            strategy=action,
                            session_id=workspace_session_id,
                            global_mapping=global_mapping,
                        )
                        # ファイル個別マッピングに追加
                        if col_name in col_mapping:
                            file_mapping[col_name] = col_mapping[col_name]
            else:
                anonymized_df = df

            # 出力（ディレクトリ構造を維持）
            output_path = airlock_path / "data" / scanned_file.relative_path.with_suffix(".csv")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            save_dataframe(anonymized_df, output_path)

            # マッピングファイル保存（ファイル個別）
            mapping_name = relative_to_mapping_name(scanned_file.relative_path)
            mapping_output = mappings_path / mapping_name
            save_mapping(file_mapping, mapping_output, password)

            # レポート用にマッピングを収集
            all_file_mappings.append(file_mapping)

            config["files"][str(scanned_file.relative_path)] = {
                "original": str(scanned_file.path),
                "anonymized": str(output_path.relative_to(airlock_path)),
                "mapping": mapping_name,
                "pii_columns": list(file_actions.keys()),
            }

            console.print(f"  [green]✓[/green] {scanned_file.relative_path}")
            processed_count += 1

        except Exception as e:
            console.print(f"  [red]✗[/red] {scanned_file.relative_path}: {e}")
            error_count += 1

    # ドキュメントファイルの処理
    if doc_files:
        from dataairlock.document_anonymizer import anonymize_document

        for scanned_file in doc_files:
            try:
                output_path = airlock_path / "data" / scanned_file.relative_path
                output_path.parent.mkdir(parents=True, exist_ok=True)

                result, doc_mapping = anonymize_document(
                    scanned_file.path,
                    output_path,
                    doc_strategy,
                )

                # ドキュメント個別マッピング
                doc_file_mapping: dict = {
                    "metadata": {
                        "created_at": datetime.now().isoformat(),
                        "original_file": str(scanned_file.path),
                        "type": "document",
                        "pii_count": result.total_matches,
                    }
                }
                if "values" in doc_mapping:
                    doc_file_mapping["values"] = doc_mapping["values"]

                # マッピングファイル保存（ファイル個別）
                mapping_name = relative_to_mapping_name(scanned_file.relative_path)
                mapping_output = mappings_path / mapping_name
                save_mapping(doc_file_mapping, mapping_output, password)

                # レポート用にマッピングを収集
                all_file_mappings.append(doc_file_mapping)

                config["files"][str(scanned_file.relative_path)] = {
                    "original": str(scanned_file.path),
                    "anonymized": str(output_path.relative_to(airlock_path)),
                    "mapping": mapping_name,
                    "type": "document",
                    "pii_count": result.total_matches,
                }

                console.print(f"  [green]✓[/green] {scanned_file.relative_path} ({result.total_matches}件のPII)")
                processed_count += 1

            except Exception as e:
                console.print(f"  [red]✗[/red] {scanned_file.relative_path}: {e}")
                error_count += 1

    # ドキュメント更新
    generate_airlock_docs(airlock_path, files)

    # マッピングレポート生成（プロジェクトルートに配置）
    if all_file_mappings:
        report_path = _generate_anonymization_report(project_dir, all_file_mappings, password)
        console.print(f"  [dim]📋 マッピングレポート: {report_path.name}[/dim]")

    # 設定保存
    _save_workspace_config(project_dir, config)

    console.print()
    console.print(Panel(
        f"[green]✅ {processed_count}ファイルを追加しました[/green]"
        + (f"\n[yellow]⚠️ {error_count}ファイルでエラー[/yellow]" if error_count else ""),
        title="🔒 完了",
    ))

    # 次のアクション
    next_action = questionary.select(
        "次のアクションは？",
        choices=[
            "🚀 AIツールを起動",
            "🔙 メニューに戻る",
        ],
        style=custom_style,
    ).ask()

    if next_action == "🚀 AIツールを起動":
        flow_launch_ai_tool(password)


def run_tui():
    """TUIメインループ"""
    try:
        while True:
            choice = main_menu()

            if choice is None or choice == "🚪 終了":
                console.print("\n[cyan]終了します[/cyan]")
                break
            elif choice == "📂 フォルダから開始（推奨）":
                flow_folder_project()
            elif choice == "📂 フォルダを追加":
                flow_add_folder()
            elif choice == "📄 ファイルから開始" or choice == "📁 ファイルを追加":
                flow_new_project()
            elif choice == "🚀 AIツールを起動":
                flow_launch_ai_tool()
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
