"""フォルダスキャンのテスト"""

import tempfile
from pathlib import Path

import pytest

from dataairlock.folder_scanner import (
    EXCLUDE_PATTERNS,
    SUPPORTED_EXTENSIONS,
    CSV_EXTENSIONS,
    DOCUMENT_EXTENSIONS,
    ScannedFile,
    count_by_type,
    format_size,
    scan_folder,
    total_size,
    relative_to_mapping_name,
    mapping_name_to_relative,
)


@pytest.fixture
def sample_folder(tmp_path):
    """サンプルフォルダ構造を作成"""
    # CSVファイル
    csv_file = tmp_path / "data.csv"
    csv_file.write_text("name,age\nAlice,30")

    # Excelファイル（空のダミー）
    xlsx_file = tmp_path / "report.xlsx"
    xlsx_file.write_bytes(b"dummy xlsx content")

    # サブフォルダ
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    sub_csv = subdir / "nested.csv"
    sub_csv.write_text("id,value\n1,100")

    return tmp_path


@pytest.fixture
def folder_with_excludes(tmp_path):
    """除外パターンを含むフォルダ"""
    # 通常ファイル
    csv_file = tmp_path / "data.csv"
    csv_file.write_text("test")

    # 除外されるべきフォルダ
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "config.csv").write_text("should be excluded")

    git = tmp_path / ".git"
    git.mkdir()
    (git / "objects.csv").write_text("should be excluded")

    pycache = tmp_path / "__pycache__"
    pycache.mkdir()
    (pycache / "cache.csv").write_text("should be excluded")

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "dep.csv").write_text("should be excluded")

    return tmp_path


class TestScannedFile:
    """ScannedFileのテスト"""

    def test_is_csv_csv(self, tmp_path):
        """CSV拡張子の判定"""
        file = ScannedFile(
            path=tmp_path / "test.csv",
            relative_path=Path("test.csv"),
            extension=".csv",
            size=100,
        )
        assert file.is_csv is True
        assert file.is_document is False

    def test_is_csv_xlsx(self, tmp_path):
        """Excel拡張子の判定"""
        file = ScannedFile(
            path=tmp_path / "test.xlsx",
            relative_path=Path("test.xlsx"),
            extension=".xlsx",
            size=100,
        )
        assert file.is_csv is True
        assert file.is_document is False

    def test_is_document_docx(self, tmp_path):
        """Word拡張子の判定"""
        file = ScannedFile(
            path=tmp_path / "test.docx",
            relative_path=Path("test.docx"),
            extension=".docx",
            size=100,
        )
        assert file.is_csv is False
        assert file.is_document is True

    def test_is_document_pptx(self, tmp_path):
        """PowerPoint拡張子の判定"""
        file = ScannedFile(
            path=tmp_path / "test.pptx",
            relative_path=Path("test.pptx"),
            extension=".pptx",
            size=100,
        )
        assert file.is_csv is False
        assert file.is_document is True

    def test_file_type_name(self, tmp_path):
        """ファイルタイプ名の取得"""
        extensions = {
            ".csv": "CSV",
            ".xlsx": "Excel",
            ".xls": "Excel",
            ".docx": "Word",
            ".pptx": "PowerPoint",
        }

        for ext, expected_name in extensions.items():
            file = ScannedFile(
                path=tmp_path / f"test{ext}",
                relative_path=Path(f"test{ext}"),
                extension=ext,
                size=100,
            )
            assert file.file_type_name == expected_name


class TestScanFolder:
    """scan_folderのテスト"""

    def test_scan_basic(self, sample_folder):
        """基本的なスキャン"""
        files = scan_folder(sample_folder)

        assert len(files) == 3
        extensions = {f.extension for f in files}
        assert ".csv" in extensions

    def test_scan_recursive(self, sample_folder):
        """再帰スキャン"""
        files = scan_folder(sample_folder, recursive=True)

        # サブフォルダのファイルも含まれる
        relative_paths = {str(f.relative_path) for f in files}
        assert any("subdir" in p for p in relative_paths)

    def test_scan_non_recursive(self, sample_folder):
        """非再帰スキャン"""
        files = scan_folder(sample_folder, recursive=False)

        # サブフォルダのファイルは含まれない
        relative_paths = {str(f.relative_path) for f in files}
        assert not any("subdir" in p for p in relative_paths)

    def test_scan_exclude_patterns(self, folder_with_excludes):
        """除外パターンのテスト"""
        files = scan_folder(folder_with_excludes)

        # 除外フォルダ内のファイルは含まれない
        for f in files:
            path_str = str(f.path)
            assert ".venv" not in path_str
            assert ".git" not in path_str
            assert "__pycache__" not in path_str
            assert "node_modules" not in path_str

        # 通常ファイルは1つだけ
        assert len(files) == 1
        assert files[0].extension == ".csv"

    def test_scan_custom_extensions(self, sample_folder):
        """カスタム拡張子フィルタ"""
        files = scan_folder(sample_folder, extensions={".csv"})

        # CSVファイルのみ
        for f in files:
            assert f.extension == ".csv"

    def test_scan_nonexistent_folder(self, tmp_path):
        """存在しないフォルダ"""
        files = scan_folder(tmp_path / "nonexistent")
        assert files == []

    def test_scan_file_not_dir(self, tmp_path):
        """ファイルをフォルダとしてスキャン"""
        file_path = tmp_path / "test.txt"
        file_path.write_text("test")

        files = scan_folder(file_path)
        assert files == []

    def test_scan_sorted_by_path(self, sample_folder):
        """パスでソートされている"""
        files = scan_folder(sample_folder)

        paths = [str(f.relative_path) for f in files]
        assert paths == sorted(paths)


class TestFormatSize:
    """format_sizeのテスト"""

    def test_bytes(self):
        """バイト単位"""
        assert format_size(0) == "0B"
        assert format_size(1) == "1B"
        assert format_size(512) == "512B"
        assert format_size(1023) == "1023B"

    def test_kilobytes(self):
        """キロバイト単位"""
        assert format_size(1024) == "1.0KB"
        assert format_size(1536) == "1.5KB"
        assert format_size(10240) == "10.0KB"

    def test_megabytes(self):
        """メガバイト単位"""
        assert format_size(1024 * 1024) == "1.0MB"
        assert format_size(1024 * 1024 * 5) == "5.0MB"

    def test_gigabytes(self):
        """ギガバイト単位"""
        assert format_size(1024 * 1024 * 1024) == "1.0GB"

    def test_terabytes(self):
        """テラバイト単位"""
        assert format_size(1024 * 1024 * 1024 * 1024) == "1.0TB"


class TestCountByType:
    """count_by_typeのテスト"""

    def test_count_mixed(self, tmp_path):
        """複数タイプのカウント"""
        files = [
            ScannedFile(tmp_path / "a.csv", Path("a.csv"), ".csv", 100),
            ScannedFile(tmp_path / "b.csv", Path("b.csv"), ".csv", 100),
            ScannedFile(tmp_path / "c.xlsx", Path("c.xlsx"), ".xlsx", 100),
            ScannedFile(tmp_path / "d.docx", Path("d.docx"), ".docx", 100),
        ]

        counts = count_by_type(files)

        assert counts["CSV"] == 2
        assert counts["Excel"] == 1
        assert counts["Word"] == 1

    def test_count_empty(self):
        """空リスト"""
        counts = count_by_type([])
        assert counts == {}


class TestTotalSize:
    """total_sizeのテスト"""

    def test_total(self, tmp_path):
        """合計サイズ"""
        files = [
            ScannedFile(tmp_path / "a.csv", Path("a.csv"), ".csv", 100),
            ScannedFile(tmp_path / "b.csv", Path("b.csv"), ".csv", 200),
            ScannedFile(tmp_path / "c.csv", Path("c.csv"), ".csv", 300),
        ]

        assert total_size(files) == 600

    def test_total_empty(self):
        """空リスト"""
        assert total_size([]) == 0


class TestExtensionSets:
    """拡張子セットのテスト"""

    def test_supported_extensions(self):
        """サポート拡張子"""
        assert ".csv" in SUPPORTED_EXTENSIONS
        assert ".xlsx" in SUPPORTED_EXTENSIONS
        assert ".xls" in SUPPORTED_EXTENSIONS
        assert ".docx" in SUPPORTED_EXTENSIONS
        assert ".pptx" in SUPPORTED_EXTENSIONS

    def test_csv_extensions(self):
        """CSV/Excel拡張子"""
        assert ".csv" in CSV_EXTENSIONS
        assert ".xlsx" in CSV_EXTENSIONS
        assert ".xls" in CSV_EXTENSIONS
        assert ".docx" not in CSV_EXTENSIONS

    def test_document_extensions(self):
        """ドキュメント拡張子"""
        assert ".docx" in DOCUMENT_EXTENSIONS
        assert ".pptx" in DOCUMENT_EXTENSIONS
        assert ".csv" not in DOCUMENT_EXTENSIONS

    def test_exclude_patterns(self):
        """除外パターン"""
        assert ".git" in EXCLUDE_PATTERNS
        assert ".venv" in EXCLUDE_PATTERNS
        assert "node_modules" in EXCLUDE_PATTERNS
        assert "__pycache__" in EXCLUDE_PATTERNS


class TestMappingNameConversion:
    """マッピングファイル名変換のテスト"""

    def test_simple_file(self):
        """単純なファイル名"""
        result = relative_to_mapping_name(Path("data.csv"))
        assert result == "data.mapping.enc"

    def test_nested_path(self):
        """ネストしたパス"""
        result = relative_to_mapping_name(Path("data/sub/file.csv"))
        assert result == "data__sub__file.mapping.enc"

    def test_deep_nested(self):
        """深いネスト"""
        result = relative_to_mapping_name(Path("a/b/c/d/file.xlsx"))
        assert result == "a__b__c__d__file.mapping.enc"

    def test_japanese_filename(self):
        """日本語ファイル名"""
        result = relative_to_mapping_name(Path("データ/患者リスト.csv"))
        assert result == "データ__患者リスト.mapping.enc"

    def test_reverse_simple(self):
        """逆変換: 単純"""
        result = mapping_name_to_relative("data.mapping.enc")
        assert result == Path("data")

    def test_reverse_nested(self):
        """逆変換: ネスト"""
        result = mapping_name_to_relative("data__sub__file.mapping.enc")
        assert result == Path("data/sub/file")

    def test_roundtrip(self):
        """往復変換"""
        original = Path("reports/monthly/sales.csv")
        mapping_name = relative_to_mapping_name(original)
        restored = mapping_name_to_relative(mapping_name)
        # 拡張子なしで比較
        assert restored == original.with_suffix("")
