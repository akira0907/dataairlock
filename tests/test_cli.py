"""CLI テスト"""

import tempfile
from pathlib import Path

import pandas as pd
import pytest
from typer.testing import CliRunner

from dataairlock.cli import app, generate_prompt_file, load_dataframe, save_dataframe
from dataairlock.anonymizer import save_mapping


runner = CliRunner()


@pytest.fixture
def sample_csv(tmp_path):
    """サンプルCSVファイルを作成"""
    csv_path = tmp_path / "test_data.csv"
    df = pd.DataFrame({
        "患者ID": ["P001", "P002", "P003"],
        "氏名": ["山田太郎", "鈴木花子", "佐藤一郎"],
        "生年月日": ["1990/01/15", "1985/03/20", "1978/12/01"],
        "住所": ["東京都新宿区西新宿1-1-1", "大阪府大阪市北区梅田2-2-2", "北海道札幌市中央区大通3-3-3"],
        "診断コード": ["A001", "B002", "C003"],
    })
    df.to_csv(csv_path, index=False)
    return csv_path


@pytest.fixture
def anonymized_data(tmp_path, sample_csv):
    """匿名化済みデータとマッピングを作成"""
    # 匿名化実行
    result = runner.invoke(app, [
        "anonymize",
        str(sample_csv),
        "-o", str(tmp_path / "output"),
        "-p", "testpassword123",
        "--auto",
    ])
    assert result.exit_code == 0

    return {
        "csv": tmp_path / "output" / "anonymized.csv",
        "mapping": tmp_path / "output" / "mapping.enc",
        "prompt": tmp_path / "output" / "prompt.txt",
        "password": "testpassword123",
    }


class TestScanCommand:
    """scan コマンドのテスト"""

    def test_scan_basic(self, sample_csv):
        """基本的なスキャン"""
        result = runner.invoke(app, ["scan", str(sample_csv)])

        assert result.exit_code == 0
        assert "患者ID" in result.output
        assert "氏名" in result.output
        assert "検出されたPII列" in result.output or "PII列" in result.output

    def test_scan_file_not_found(self, tmp_path):
        """存在しないファイル"""
        result = runner.invoke(app, ["scan", str(tmp_path / "nonexistent.csv")])

        assert result.exit_code == 1
        assert "ファイルが見つかりません" in result.output

    def test_scan_no_pii(self, tmp_path):
        """PII列がないファイル"""
        csv_path = tmp_path / "no_pii.csv"
        df = pd.DataFrame({
            "商品コード": ["A001", "A002"],
            "価格": [100, 200],
        })
        df.to_csv(csv_path, index=False)

        result = runner.invoke(app, ["scan", str(csv_path)])

        assert result.exit_code == 0
        assert "個人情報なし" in result.output or "検出されませんでした" in result.output


class TestAnonymizeCommand:
    """anonymize コマンドのテスト"""

    def test_anonymize_auto(self, sample_csv, tmp_path):
        """自動モードでの匿名化"""
        output_dir = tmp_path / "output"

        result = runner.invoke(app, [
            "anonymize",
            str(sample_csv),
            "-o", str(output_dir),
            "-p", "testpassword123",
            "--auto",
        ])

        assert result.exit_code == 0
        assert "匿名化が完了しました" in result.output

        # 出力ファイルの確認
        assert (output_dir / "anonymized.csv").exists()
        assert (output_dir / "mapping.enc").exists()
        assert (output_dir / "prompt.txt").exists()

    def test_anonymize_output_content(self, sample_csv, tmp_path):
        """匿名化された内容の確認"""
        output_dir = tmp_path / "output"

        runner.invoke(app, [
            "anonymize",
            str(sample_csv),
            "-o", str(output_dir),
            "-p", "testpassword123",
            "--auto",
        ])

        # CSVの内容確認
        anon_df = pd.read_csv(output_dir / "anonymized.csv")

        # 元の値が残っていないことを確認
        assert "P001" not in anon_df["患者ID"].values
        assert "山田太郎" not in anon_df["氏名"].values

        # ANON_で始まる値があることを確認
        assert any(str(v).startswith("ANON_") for v in anon_df["患者ID"].values)

    def test_anonymize_generalize_strategy(self, sample_csv, tmp_path):
        """generalize戦略"""
        output_dir = tmp_path / "output"

        result = runner.invoke(app, [
            "anonymize",
            str(sample_csv),
            "-o", str(output_dir),
            "-p", "testpassword123",
            "-s", "generalize",
            "--auto",
        ])

        assert result.exit_code == 0

        anon_df = pd.read_csv(output_dir / "anonymized.csv")

        # 住所が都道府県に一般化されていることを確認
        assert "東京都" in anon_df["住所"].values
        assert "大阪府" in anon_df["住所"].values

    def test_anonymize_file_not_found(self, tmp_path):
        """存在しないファイル"""
        result = runner.invoke(app, [
            "anonymize",
            str(tmp_path / "nonexistent.csv"),
            "-p", "testpassword",
        ])

        assert result.exit_code == 1
        assert "ファイルが見つかりません" in result.output

    def test_anonymize_invalid_strategy(self, sample_csv, tmp_path):
        """無効な戦略"""
        result = runner.invoke(app, [
            "anonymize",
            str(sample_csv),
            "-o", str(tmp_path),
            "-p", "testpassword",
            "-s", "invalid_strategy",
            "--auto",
        ])

        assert result.exit_code == 1
        assert "無効な戦略" in result.output

    def test_anonymize_prompt_file_content(self, sample_csv, tmp_path):
        """プロンプトファイルの内容確認"""
        output_dir = tmp_path / "output"

        runner.invoke(app, [
            "anonymize",
            str(sample_csv),
            "-o", str(output_dir),
            "-p", "testpassword123",
            "--auto",
        ])

        prompt_content = (output_dir / "prompt.txt").read_text(encoding="utf-8")

        assert "匿名化済みデータ" in prompt_content
        assert "test_data.csv" in prompt_content
        assert "ANON_" in prompt_content


class TestRestoreCommand:
    """restore コマンドのテスト"""

    def test_restore_basic(self, anonymized_data, tmp_path):
        """基本的な復元"""
        output_path = tmp_path / "restored.csv"

        result = runner.invoke(app, [
            "restore",
            str(anonymized_data["csv"]),
            "-m", str(anonymized_data["mapping"]),
            "-p", anonymized_data["password"],
            "-o", str(output_path),
        ])

        assert result.exit_code == 0
        assert "復元が完了しました" in result.output
        assert output_path.exists()

    def test_restore_content(self, anonymized_data, tmp_path):
        """復元内容の確認"""
        output_path = tmp_path / "restored.csv"

        runner.invoke(app, [
            "restore",
            str(anonymized_data["csv"]),
            "-m", str(anonymized_data["mapping"]),
            "-p", anonymized_data["password"],
            "-o", str(output_path),
        ])

        restored_df = pd.read_csv(output_path)

        # 元の値が復元されていることを確認
        assert "P001" in restored_df["患者ID"].values
        assert "山田太郎" in restored_df["氏名"].values

    def test_restore_wrong_password(self, anonymized_data, tmp_path):
        """間違ったパスワード"""
        result = runner.invoke(app, [
            "restore",
            str(anonymized_data["csv"]),
            "-m", str(anonymized_data["mapping"]),
            "-p", "wrongpassword",
            "-o", str(tmp_path / "restored.csv"),
        ])

        assert result.exit_code == 1
        assert "パスワードが正しくない" in result.output

    def test_restore_missing_mapping(self, anonymized_data, tmp_path):
        """マッピングファイルが存在しない"""
        result = runner.invoke(app, [
            "restore",
            str(anonymized_data["csv"]),
            "-m", str(tmp_path / "nonexistent.enc"),
            "-p", "testpassword",
        ])

        assert result.exit_code == 1
        assert "マッピングファイルが見つかりません" in result.output


class TestUtilityFunctions:
    """ユーティリティ関数のテスト"""

    def test_load_dataframe_csv(self, tmp_path):
        """CSV読み込み"""
        csv_path = tmp_path / "test.csv"
        pd.DataFrame({"a": [1, 2]}).to_csv(csv_path, index=False)

        df = load_dataframe(csv_path)
        assert len(df) == 2

    def test_load_dataframe_excel(self, tmp_path):
        """Excel読み込み"""
        xlsx_path = tmp_path / "test.xlsx"
        pd.DataFrame({"a": [1, 2]}).to_excel(xlsx_path, index=False)

        df = load_dataframe(xlsx_path)
        assert len(df) == 2

    def test_save_dataframe_bom(self, tmp_path):
        """UTF-8 BOM付きで保存"""
        csv_path = tmp_path / "test.csv"
        df = pd.DataFrame({"名前": ["山田", "鈴木"]})

        save_dataframe(df, csv_path)

        # BOMの確認
        with open(csv_path, "rb") as f:
            first_bytes = f.read(3)
        assert first_bytes == b'\xef\xbb\xbf'

    def test_generate_prompt_file(self):
        """プロンプト生成"""
        prompt = generate_prompt_file(
            original_filename="test.csv",
            row_count=100,
            columns=["患者ID", "氏名", "診断コード"],
            anonymized_info=[
                {"column": "患者ID", "action": "replaced"},
                {"column": "氏名", "action": "replaced"},
            ],
        )

        assert "test.csv" in prompt
        assert "100" in prompt
        assert "患者ID" in prompt
        assert "replace" in prompt


class TestHelpMessages:
    """ヘルプメッセージのテスト"""

    def test_main_help(self):
        """メインヘルプ"""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "anonymize" in result.output
        assert "restore" in result.output
        assert "scan" in result.output

    def test_anonymize_help(self):
        """anonymizeヘルプ"""
        result = runner.invoke(app, ["anonymize", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--password" in result.output
        assert "--strategy" in result.output

    def test_restore_help(self):
        """restoreヘルプ"""
        result = runner.invoke(app, ["restore", "--help"])
        assert result.exit_code == 0
        assert "--mapping" in result.output
        assert "--password" in result.output

    def test_scan_help(self):
        """scanヘルプ"""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_workspace_help(self):
        """workspaceヘルプ"""
        result = runner.invoke(app, ["workspace", "--help"])
        assert result.exit_code == 0
        assert "--add" in result.output
        assert "--status" in result.output
        assert "--restore" in result.output
        assert "--clean" in result.output


class TestWorkspaceCommand:
    """workspace コマンドのテスト"""

    def test_workspace_add_file(self, tmp_path, sample_csv):
        """ファイル追加でワークスペース作成"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # サンプルCSVをプロジェクトにコピー
        data_dir = project_dir / "data"
        data_dir.mkdir()
        import shutil
        shutil.copy(sample_csv, data_dir / "test_data.csv")

        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add", "data/test_data.csv",
            "-p", "testpassword123",
        ], input="r\nr\ng\ng\n")  # 各PII列の処理方法

        assert result.exit_code == 0
        assert "ワークスペースを作成しました" in result.output

        # ディレクトリ構造の確認
        airlock_path = project_dir / ".airlock"
        assert airlock_path.exists()
        assert (airlock_path / "data").exists()
        assert (airlock_path / ".mapping").exists()
        assert (airlock_path / "output").exists()
        assert (airlock_path / "README.md").exists()
        assert (airlock_path / "PROMPT.md").exists()
        assert (airlock_path / ".gitignore").exists()

        # 匿名化ファイルの確認
        assert (airlock_path / "data" / "test_data.csv").exists()
        assert (airlock_path / ".mapping" / "test_data.mapping.enc").exists()

    def test_workspace_status(self, tmp_path, sample_csv):
        """ステータス表示"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # サンプルCSVをプロジェクトにコピー
        data_dir = project_dir / "data"
        data_dir.mkdir()
        import shutil
        shutil.copy(sample_csv, data_dir / "test_data.csv")

        # ワークスペース作成
        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add", "data/test_data.csv",
            "-p", "testpassword123",
        ], input="r\nr\ng\ng\n")

        # ステータス確認
        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--status",
        ])

        assert result.exit_code == 0
        assert "ワークスペース情報" in result.output
        assert "test_data" in result.output

    def test_workspace_status_no_workspace(self, tmp_path):
        """ワークスペースがない場合のステータス"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--status",
        ])

        assert result.exit_code == 0
        assert "ワークスペースが見つかりません" in result.output

    def test_workspace_clean(self, tmp_path, sample_csv):
        """ワークスペースの削除"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # サンプルCSVをプロジェクトにコピー
        data_dir = project_dir / "data"
        data_dir.mkdir()
        import shutil
        shutil.copy(sample_csv, data_dir / "test_data.csv")

        # ワークスペース作成
        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add", "data/test_data.csv",
            "-p", "testpassword123",
        ], input="r\nr\ng\ng\n")

        airlock_path = project_dir / ".airlock"
        assert airlock_path.exists()

        # 削除
        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--clean",
        ], input="y\n")

        assert result.exit_code == 0
        assert "削除しました" in result.output
        assert not airlock_path.exists()

    def test_workspace_restore(self, tmp_path, sample_csv):
        """結果の復元"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # サンプルCSVをプロジェクトにコピー
        data_dir = project_dir / "data"
        data_dir.mkdir()
        import shutil
        shutil.copy(sample_csv, data_dir / "test_data.csv")

        # ワークスペース作成
        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add", "data/test_data.csv",
            "-p", "testpassword123",
        ], input="r\nr\ng\ng\n")

        # 匿名化されたファイルをoutputにコピー（Claude Codeの出力をシミュレート）
        airlock_path = project_dir / ".airlock"
        output_dir = airlock_path / "output"
        shutil.copy(airlock_path / "data" / "test_data.csv", output_dir / "result.csv")

        # 復元
        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--restore", "output/result.csv",
            "-p", "testpassword123",
        ])

        assert result.exit_code == 0
        assert "復元が完了しました" in result.output

        # 復元ファイルの確認
        results_dir = project_dir / "results"
        assert results_dir.exists()
        assert (results_dir / "result.csv").exists()

        # 復元内容の確認
        restored_df = pd.read_csv(results_dir / "result.csv")
        assert "P001" in restored_df["患者ID"].values
        assert "山田太郎" in restored_df["氏名"].values

    def test_workspace_gitignore_content(self, tmp_path, sample_csv):
        """.gitignoreの内容確認"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # サンプルCSVをプロジェクトにコピー
        data_dir = project_dir / "data"
        data_dir.mkdir()
        import shutil
        shutil.copy(sample_csv, data_dir / "test_data.csv")

        # ワークスペース作成
        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add", "data/test_data.csv",
            "-p", "testpassword123",
        ], input="r\nr\ng\ng\n")

        # .gitignoreの内容確認
        gitignore_path = project_dir / ".airlock" / ".gitignore"
        content = gitignore_path.read_text()

        assert ".mapping/" in content
        assert "*.enc" in content

    def test_workspace_prompt_md_content(self, tmp_path, sample_csv):
        """PROMPT.mdの内容確認"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # サンプルCSVをプロジェクトにコピー
        data_dir = project_dir / "data"
        data_dir.mkdir()
        import shutil
        shutil.copy(sample_csv, data_dir / "test_data.csv")

        # ワークスペース作成
        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add", "data/test_data.csv",
            "-p", "testpassword123",
        ], input="r\nr\ng\ng\n")

        # PROMPT.mdの内容確認
        prompt_path = project_dir / ".airlock" / "PROMPT.md"
        content = prompt_path.read_text()

        assert "利用可能なデータ" in content
        assert "test_data" in content
        assert "ANON_" in content

    def test_workspace_anonymized_content(self, tmp_path, sample_csv):
        """匿名化されたファイルの内容確認"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # サンプルCSVをプロジェクトにコピー
        data_dir = project_dir / "data"
        data_dir.mkdir()
        import shutil
        shutil.copy(sample_csv, data_dir / "test_data.csv")

        # ワークスペース作成
        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add", "data/test_data.csv",
            "-p", "testpassword123",
        ], input="r\nr\ng\ng\n")

        # 匿名化ファイルの内容確認
        anon_path = project_dir / ".airlock" / "data" / "test_data.csv"
        anon_df = pd.read_csv(anon_path)

        # 元の値が残っていないことを確認
        assert "P001" not in anon_df["患者ID"].values
        assert "山田太郎" not in anon_df["氏名"].values

        # ANON_で始まる値があることを確認
        assert any(str(v).startswith("ANON_") for v in anon_df["患者ID"].values)

    def test_workspace_add_all(self, tmp_path):
        """--add-all: フォルダ内の全ファイルを一括追加"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # raw_data フォルダにCSVファイルを作成
        raw_data = project_dir / "raw_data"
        raw_data.mkdir()

        # ファイル1
        df1 = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
            "診断": ["A001", "B002"],
        })
        df1.to_csv(raw_data / "file1.csv", index=False)

        # ファイル2
        df2 = pd.DataFrame({
            "患者ID": ["P003", "P004"],
            "氏名": ["佐藤一郎", "田中二郎"],
            "処方": ["C001", "D002"],
        })
        df2.to_csv(raw_data / "file2.csv", index=False)

        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add-all", "raw_data",
            "-p", "testpassword123",
        ], input="r\nr\n")  # 患者ID, 氏名 の処理方法

        assert result.exit_code == 0
        assert "2ファイルを匿名化しました" in result.output

        # ファイルが作成されていることを確認
        airlock_path = project_dir / ".airlock"
        assert (airlock_path / "data" / "file1.csv").exists()
        assert (airlock_path / "data" / "file2.csv").exists()
        assert (airlock_path / ".mapping" / "file1.mapping.enc").exists()
        assert (airlock_path / ".mapping" / "file2.mapping.enc").exists()

        # 匿名化されていることを確認
        anon_df1 = pd.read_csv(airlock_path / "data" / "file1.csv")
        assert "P001" not in anon_df1["患者ID"].values
        assert any(str(v).startswith("ANON_") for v in anon_df1["患者ID"].values)

    def test_workspace_add_all_no_files(self, tmp_path):
        """--add-all: フォルダにCSVがない場合"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # 空フォルダ
        empty_folder = project_dir / "empty"
        empty_folder.mkdir()

        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add-all", "empty",
        ])

        assert result.exit_code == 0
        assert "CSV/Excelファイルがありません" in result.output

    def test_workspace_restore_all(self, tmp_path):
        """--restore-all: output内の全CSVを一括復元"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # raw_data フォルダにCSVファイルを作成
        raw_data = project_dir / "raw_data"
        raw_data.mkdir()

        df1 = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
        })
        df1.to_csv(raw_data / "data.csv", index=False)

        # ワークスペース作成
        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add-all", "raw_data",
            "-p", "testpassword123",
        ], input="r\nr\n")

        # 匿名化ファイルをoutputにコピー（Claude Codeの出力をシミュレート）
        airlock_path = project_dir / ".airlock"
        import shutil
        shutil.copy(airlock_path / "data" / "data.csv", airlock_path / "output" / "result1.csv")
        shutil.copy(airlock_path / "data" / "data.csv", airlock_path / "output" / "result2.csv")

        # 一括復元
        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--restore-all",
            "-p", "testpassword123",
        ])

        assert result.exit_code == 0
        assert "2ファイルを復元しました" in result.output

        # 復元ファイルの確認
        results_dir = project_dir / "results"
        assert (results_dir / "result1.csv").exists()
        assert (results_dir / "result2.csv").exists()

        # 復元内容の確認
        restored_df = pd.read_csv(results_dir / "result1.csv")
        assert "P001" in restored_df["患者ID"].values
        assert "山田太郎" in restored_df["氏名"].values

    def test_workspace_restore_all_no_files(self, tmp_path):
        """--restore-all: outputにCSVがない場合"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # PIIありのファイルでワークスペースを作成
        raw_data = project_dir / "raw_data"
        raw_data.mkdir()
        df = pd.DataFrame({
            "患者ID": ["P001"],
            "氏名": ["テスト"],
        })
        df.to_csv(raw_data / "test.csv", index=False)

        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add-all", "raw_data",
            "-p", "testpassword123",
        ], input="r\nr\n")  # 患者ID, 氏名 の処理方法

        # outputを空にする（ファイルを削除）
        airlock_path = project_dir / ".airlock"
        output_dir = airlock_path / "output"
        for f in output_dir.glob("*.csv"):
            f.unlink()

        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--restore-all",
        ])

        assert result.exit_code == 0
        assert "CSVファイルがありません" in result.output

    def test_workspace_restore_all_recursive(self, tmp_path):
        """--restore-all: サブディレクトリを再帰的に復元"""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # raw_data フォルダにCSVファイルを作成
        raw_data = project_dir / "raw_data"
        raw_data.mkdir()

        df = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
        })
        df.to_csv(raw_data / "data.csv", index=False)

        # ワークスペース作成
        runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--add-all", "raw_data",
            "-p", "testpassword123",
        ], input="r\nr\n")

        # サブディレクトリを作成してファイルをコピー
        airlock_path = project_dir / ".airlock"
        output_dir = airlock_path / "output"

        # 階層構造を作成
        import shutil
        monthly_dir = output_dir / "monthly"
        monthly_dir.mkdir()
        weekly_dir = output_dir / "reports" / "weekly"
        weekly_dir.mkdir(parents=True)

        shutil.copy(airlock_path / "data" / "data.csv", output_dir / "root.csv")
        shutil.copy(airlock_path / "data" / "data.csv", monthly_dir / "report.csv")
        shutil.copy(airlock_path / "data" / "data.csv", weekly_dir / "summary.csv")

        # 一括復元
        result = runner.invoke(app, [
            "workspace",
            str(project_dir),
            "--restore-all",
            "-p", "testpassword123",
        ])

        assert result.exit_code == 0
        assert "3ファイルを復元しました" in result.output

        # 復元ファイルとディレクトリ構造の確認
        results_dir = project_dir / "results"
        assert (results_dir / "root.csv").exists()
        assert (results_dir / "monthly" / "report.csv").exists()
        assert (results_dir / "reports" / "weekly" / "summary.csv").exists()

        # 復元内容の確認
        restored_df = pd.read_csv(results_dir / "monthly" / "report.csv")
        assert "P001" in restored_df["患者ID"].values
        assert "山田太郎" in restored_df["氏名"].values
