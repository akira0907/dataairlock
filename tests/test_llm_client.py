"""LLMクライアントのテスト"""

import pytest
from unittest.mock import patch, MagicMock

from dataairlock.llm_client import (
    is_ollama_installed,
    is_ollama_running,
    get_available_models,
    start_ollama_server,
    get_ollama_install_instructions,
    LLMClient,
    OLLAMA_AVAILABLE,
)


class TestOllamaUtilities:
    """Ollamaユーティリティ関数のテスト"""

    @patch("shutil.which")
    def test_is_ollama_installed_true(self, mock_which):
        """Ollamaがインストールされている場合"""
        mock_which.return_value = "/usr/local/bin/ollama"
        assert is_ollama_installed() is True

    @patch("shutil.which")
    def test_is_ollama_installed_false(self, mock_which):
        """Ollamaがインストールされていない場合"""
        mock_which.return_value = None
        assert is_ollama_installed() is False

    def test_get_ollama_install_instructions_darwin(self):
        """macOS用インストール手順"""
        with patch("sys.platform", "darwin"):
            instructions = get_ollama_install_instructions()
            assert "brew" in instructions or "ollama.ai" in instructions

    def test_get_ollama_install_instructions_linux(self):
        """Linux用インストール手順"""
        with patch("sys.platform", "linux"):
            instructions = get_ollama_install_instructions()
            assert "curl" in instructions or "ollama.ai" in instructions

    def test_get_ollama_install_instructions_windows(self):
        """Windows用インストール手順"""
        with patch("sys.platform", "win32"):
            instructions = get_ollama_install_instructions()
            assert "ollama.ai" in instructions


class TestLLMClient:
    """LLMClient クラスのテスト"""

    def test_init_default_model(self):
        """デフォルトモデルでの初期化"""
        client = LLMClient()
        assert client.model == "llama3.1:8b"
        assert client.messages == []
        assert client.system_prompt is None

    def test_init_custom_model(self):
        """カスタムモデルでの初期化"""
        client = LLMClient(model="llama2:7b")
        assert client.model == "llama2:7b"

    def test_set_system_prompt(self):
        """システムプロンプトの設定"""
        client = LLMClient()
        client.set_system_prompt("You are a helpful assistant.")
        assert client.system_prompt == "You are a helpful assistant."

    def test_reset(self):
        """会話履歴のリセット"""
        client = LLMClient()
        client.messages = [{"role": "user", "content": "test"}]
        client.reset()
        assert client.messages == []

    def test_build_messages_without_system(self):
        """システムプロンプトなしでのメッセージ構築"""
        client = LLMClient()
        client.messages = [{"role": "user", "content": "Hello"}]
        messages = client._build_messages()
        assert len(messages) == 1
        assert messages[0]["role"] == "user"

    def test_build_messages_with_system(self):
        """システムプロンプトありでのメッセージ構築"""
        client = LLMClient()
        client.set_system_prompt("System prompt")
        client.messages = [{"role": "user", "content": "Hello"}]
        messages = client._build_messages()
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "System prompt"
        assert messages[1]["role"] == "user"

    def test_extract_json_from_code_block(self):
        """コードブロックからJSONを抽出"""
        client = LLMClient()
        text = '''Here is the result:
```json
[{"type": "NAME", "value": "山田太郎"}]
```
'''
        result = client._extract_json(text)
        assert result == '[{"type": "NAME", "value": "山田太郎"}]'

    def test_extract_json_direct(self):
        """直接JSON配列を抽出"""
        client = LLMClient()
        text = '[{"type": "NAME", "value": "山田太郎"}]'
        result = client._extract_json(text)
        assert result == '[{"type": "NAME", "value": "山田太郎"}]'

    def test_extract_json_no_json(self):
        """JSONが含まれない場合"""
        client = LLMClient()
        text = "No JSON here"
        result = client._extract_json(text)
        assert result is None

    @patch("dataairlock.llm_client.OLLAMA_AVAILABLE", False)
    def test_detect_pii_no_ollama(self):
        """Ollamaが利用できない場合のPII検出"""
        client = LLMClient()
        result = client.detect_pii("山田太郎")
        assert result == []

    @patch("dataairlock.llm_client.is_ollama_running")
    def test_detect_pii_not_running(self, mock_running):
        """Ollamaが起動していない場合のPII検出"""
        mock_running.return_value = False
        client = LLMClient()
        result = client.detect_pii("山田太郎")
        assert result == []


class TestIsOllamaRunning:
    """is_ollama_running のテスト"""

    @patch("dataairlock.llm_client.OLLAMA_AVAILABLE", False)
    def test_ollama_not_available(self):
        """ollama パッケージが利用できない場合"""
        assert is_ollama_running() is False


class TestGetAvailableModels:
    """get_available_models のテスト"""

    @patch("dataairlock.llm_client.is_ollama_running")
    def test_not_running(self, mock_running):
        """サーバーが起動していない場合"""
        mock_running.return_value = False
        assert get_available_models() == []


class TestStartOllamaServer:
    """start_ollama_server のテスト"""

    @patch("dataairlock.llm_client.is_ollama_installed")
    def test_not_installed(self, mock_installed):
        """Ollamaがインストールされていない場合"""
        mock_installed.return_value = False
        assert start_ollama_server() is False
