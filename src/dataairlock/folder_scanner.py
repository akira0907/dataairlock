"""フォルダスキャン機能"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# 対象ファイル拡張子
SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".xls", ".docx", ".pptx"}
CSV_EXTENSIONS = {".csv", ".xlsx", ".xls"}
DOCUMENT_EXTENSIONS = {".docx", ".pptx"}

# 除外パターン
EXCLUDE_PATTERNS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".airlock",
    ".airlock_mappings",
    "results",
    ".DS_Store",
}


@dataclass
class ScannedFile:
    """スキャンされたファイル情報"""

    path: Path
    relative_path: Path  # ルートからの相対パス
    extension: str
    size: int

    @property
    def is_csv(self) -> bool:
        """CSVまたはExcelファイルか"""
        return self.extension in CSV_EXTENSIONS

    @property
    def is_document(self) -> bool:
        """Word/PowerPointファイルか"""
        return self.extension in DOCUMENT_EXTENSIONS

    @property
    def file_type_name(self) -> str:
        """ファイルタイプの表示名"""
        type_map = {
            ".csv": "CSV",
            ".xlsx": "Excel",
            ".xls": "Excel",
            ".docx": "Word",
            ".pptx": "PowerPoint",
        }
        return type_map.get(self.extension, self.extension)


def scan_folder(
    root: Path,
    recursive: bool = True,
    extensions: set | None = None,
) -> list[ScannedFile]:
    """
    フォルダをスキャンして対象ファイルを列挙

    Args:
        root: スキャン対象フォルダ
        recursive: サブフォルダも含めるか
        extensions: 対象拡張子（Noneの場合はデフォルト）

    Returns:
        スキャンされたファイルのリスト
    """
    if extensions is None:
        extensions = SUPPORTED_EXTENSIONS

    files: list[ScannedFile] = []
    root = Path(root).resolve()

    if not root.exists():
        return files

    if not root.is_dir():
        return files

    def should_exclude(path: Path) -> bool:
        """除外パターンに一致するか"""
        return any(ex in path.parts for ex in EXCLUDE_PATTERNS)

    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            # 除外ディレクトリをスキップ
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_PATTERNS]

            for filename in filenames:
                filepath = Path(dirpath) / filename
                if should_exclude(filepath):
                    continue

                ext = filepath.suffix.lower()
                if ext in extensions:
                    try:
                        files.append(
                            ScannedFile(
                                path=filepath,
                                relative_path=filepath.relative_to(root),
                                extension=ext,
                                size=filepath.stat().st_size,
                            )
                        )
                    except OSError:
                        pass
    else:
        for filepath in root.iterdir():
            if filepath.is_file() and not should_exclude(filepath):
                ext = filepath.suffix.lower()
                if ext in extensions:
                    try:
                        files.append(
                            ScannedFile(
                                path=filepath,
                                relative_path=filepath.relative_to(root),
                                extension=ext,
                                size=filepath.stat().st_size,
                            )
                        )
                    except OSError:
                        pass

    return sorted(files, key=lambda f: str(f.relative_path))


def format_size(size: int) -> str:
    """ファイルサイズを人間が読める形式に"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            if unit == "B":
                return f"{size}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def count_by_type(files: list[ScannedFile]) -> dict[str, int]:
    """ファイルタイプ別にカウント"""
    counts: dict[str, int] = {}
    for f in files:
        type_name = f.file_type_name
        counts[type_name] = counts.get(type_name, 0) + 1
    return counts


def total_size(files: list[ScannedFile]) -> int:
    """合計サイズを計算"""
    return sum(f.size for f in files)


def relative_to_mapping_name(relative_path: Path) -> str:
    """
    相対パスからマッピングファイル名を生成

    例: data/sub/file.csv → data__sub__file.mapping.enc

    Args:
        relative_path: ルートからの相対パス

    Returns:
        マッピングファイル名
    """
    parts = list(relative_path.parts)
    # 最後のパートから拡張子を除去
    name = parts[-1].rsplit(".", 1)[0]
    parts[-1] = name
    return "__".join(parts) + ".mapping.enc"


def mapping_name_to_relative(mapping_name: str) -> Path:
    """
    マッピングファイル名から相対パスを復元

    例: data__sub__file.mapping.enc → data/sub/file

    Args:
        mapping_name: マッピングファイル名

    Returns:
        相対パス（拡張子なし）
    """
    # .mapping.enc を除去
    base = mapping_name.replace(".mapping.enc", "")
    # __ で分割してパスに変換
    parts = base.split("__")
    return Path(*parts)
