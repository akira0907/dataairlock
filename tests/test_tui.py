"""TUI テスト"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from dataairlock.tui import (
    _get_airlock_path,
    _get_mappings_path,
    _init_workspace,
    _load_workspace_config,
    _save_workspace_config,
    get_password,
    load_dataframe,
    save_dataframe,
    show_status,
)


class TestTUIHelperFunctions:
    """TUIヘルパー関数のテスト"""

    def test_get_airlock_path(self, tmp_path):
        """airlockパス取得"""
        result = _get_airlock_path(tmp_path)
        assert result == tmp_path / ".airlock"

    def test_get_mappings_path(self, tmp_path):
        """マッピングパス取得"""
        result = _get_mappings_path(tmp_path)
        assert result == tmp_path / ".airlock_mappings"

    def test_init_workspace(self, tmp_path):
        """ワークスペース初期化"""
        airlock_path = _init_workspace(tmp_path)

        assert airlock_path.exists()
        assert (airlock_path / "data").exists()
        assert (airlock_path / "output").exists()
        assert (tmp_path / ".airlock_mappings").exists()
        assert (airlock_path / ".gitignore").exists()

    def test_save_and_load_workspace_config(self, tmp_path):
        """設定の保存と読み込み"""
        # ワークスペース初期化
        _init_workspace(tmp_path)

        config = {
            "created_at": "2024-01-01T00:00:00",
            "files": {"test": {"name": "test.csv"}},
        }
        _save_workspace_config(tmp_path, config)

        loaded = _load_workspace_config(tmp_path)
        assert loaded == config

    def test_load_workspace_config_not_exists(self, tmp_path):
        """存在しない設定の読み込み"""
        result = _load_workspace_config(tmp_path)
        assert result is None


class TestTUIDataframeFunctions:
    """DataFrame関連のテスト"""

    def test_load_dataframe_csv(self, tmp_path):
        """CSV読み込み"""
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("a,b\n1,2\n3,4")

        df = load_dataframe(csv_file)
        assert len(df) == 2
        assert list(df.columns) == ["a", "b"]

    def test_load_dataframe_unsupported(self, tmp_path):
        """サポートされていない形式"""
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("content")

        with pytest.raises(ValueError, match="サポートされていない"):
            load_dataframe(txt_file)

    def test_save_dataframe(self, tmp_path):
        """DataFrame保存（UTF-8 BOM付き）"""
        df = pd.DataFrame({"名前": ["山田太郎"], "年齢": [30]})
        output_file = tmp_path / "output.csv"

        save_dataframe(df, output_file)

        assert output_file.exists()
        # BOMが付いていることを確認
        with open(output_file, "rb") as f:
            content = f.read()
            assert content.startswith(b'\xef\xbb\xbf')


class TestTUIStatusFunctions:
    """ステータス表示のテスト"""

    def test_show_status_no_workspace(self, tmp_path, capsys):
        """ワークスペースがない場合"""
        result = show_status(tmp_path)
        assert result is False

    def test_show_status_with_workspace(self, tmp_path, capsys):
        """ワークスペースがある場合"""
        _init_workspace(tmp_path)
        config = {
            "created_at": "2024-01-01T00:00:00",
            "files": {"test": {"name": "test.csv", "pii_columns": ["氏名"]}},
        }
        _save_workspace_config(tmp_path, config)

        result = show_status(tmp_path)
        assert result is True


class TestTUIPasswordFunctions:
    """パスワード関連のテスト"""

    @patch('questionary.password')
    def test_get_password_mismatch(self, mock_password):
        """パスワード不一致"""
        mock_ask = MagicMock()
        mock_ask.ask.side_effect = ["pass1", "pass2"]
        mock_password.return_value = mock_ask

        result = get_password(confirm=True)
        assert result is None

    @patch('questionary.password')
    def test_get_password_success(self, mock_password):
        """パスワード成功"""
        mock_ask = MagicMock()
        mock_ask.ask.side_effect = ["testpass123", "testpass123"]
        mock_password.return_value = mock_ask

        result = get_password(confirm=True)
        assert result == "testpass123"

    @patch('questionary.password')
    def test_get_password_no_confirm(self, mock_password):
        """確認なしのパスワード入力"""
        mock_ask = MagicMock()
        mock_ask.ask.return_value = "testpass123"
        mock_password.return_value = mock_ask

        result = get_password(confirm=False)
        assert result == "testpass123"

    @patch('questionary.password')
    def test_get_password_empty(self, mock_password):
        """空のパスワード"""
        mock_ask = MagicMock()
        mock_ask.ask.return_value = ""
        mock_password.return_value = mock_ask

        result = get_password(confirm=False)
        assert result is None


class TestTUIIntegration:
    """TUI統合テスト"""

    @patch('dataairlock.tui.questionary')
    def test_main_menu_no_workspace(self, mock_questionary, tmp_path, monkeypatch):
        """ワークスペースなしのメインメニュー"""
        monkeypatch.chdir(tmp_path)

        mock_select = MagicMock()
        mock_select.ask.return_value = "🚪 終了"
        mock_questionary.select.return_value = mock_select

        from dataairlock.tui import main_menu
        result = main_menu()

        # selectが呼ばれていることを確認
        mock_questionary.select.assert_called_once()

    @patch('dataairlock.tui.questionary')
    def test_main_menu_with_workspace(self, mock_questionary, tmp_path, monkeypatch):
        """ワークスペースありのメインメニュー"""
        monkeypatch.chdir(tmp_path)
        _init_workspace(tmp_path)

        mock_select = MagicMock()
        mock_select.ask.return_value = "🚪 終了"
        mock_questionary.select.return_value = mock_select

        from dataairlock.tui import main_menu
        result = main_menu()

        # selectが呼ばれていることを確認
        mock_questionary.select.assert_called_once()
