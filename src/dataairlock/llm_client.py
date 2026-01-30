"""Ollama ローカルLLM連携"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Generator

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


def is_ollama_installed() -> bool:
    """Ollamaがインストールされているかチェック"""
    return shutil.which("ollama") is not None


def is_ollama_running() -> bool:
    """Ollamaサーバーが起動しているかチェック"""
    if not OLLAMA_AVAILABLE:
        return False
    try:
        ollama.list()
        return True
    except Exception:
        return False


def get_available_models() -> list[str]:
    """利用可能なOllamaモデル一覧を取得"""
    if not is_ollama_running():
        return []
    try:
        result = ollama.list()
        # ollama library returns Pydantic model, access .models attribute
        return [m.model for m in result.models]
    except Exception:
        return []


def start_ollama_server() -> bool:
    """Ollamaサーバーを起動"""
    if not is_ollama_installed():
        return False
    try:
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # 起動待機
        import time
        for _ in range(10):
            time.sleep(1)
            if is_ollama_running():
                return True
        return False
    except Exception:
        return False


def pull_model(model: str) -> bool:
    """Ollamaモデルをダウンロード"""
    if not is_ollama_running():
        return False
    try:
        ollama.pull(model)
        return True
    except Exception:
        return False


def get_ollama_install_instructions() -> str:
    """Ollamaインストール手順を取得"""
    if sys.platform == "darwin":
        return "brew install ollama または https://ollama.ai からダウンロード"
    elif sys.platform == "linux":
        return "curl -fsSL https://ollama.ai/install.sh | sh"
    elif sys.platform == "win32":
        return "https://ollama.ai からインストーラーをダウンロード"
    else:
        return "https://ollama.ai を参照"


class LLMClient:
    """Ollamaを使ったローカルLLMクライアント"""

    def __init__(self, model: str = "llama3.1:8b"):
        self.model = model
        self.messages: list[dict] = []
        self.system_prompt: str | None = None

    def set_system_prompt(self, prompt: str) -> None:
        """システムプロンプトを設定"""
        self.system_prompt = prompt

    def reset(self) -> None:
        """会話履歴をリセット"""
        self.messages = []

    def detect_pii(self, text: str) -> list[dict]:
        """
        テキストから個人情報を検出する（LLMベース）

        Args:
            text: 検査対象のテキスト

        Returns:
            検出されたPIIのリスト
            [{"type": "NAME", "value": "山田太郎", "confidence": "high"}, ...]
        """
        if not OLLAMA_AVAILABLE or not is_ollama_running():
            return []

        prompt = f"""以下のテキストから個人情報（PII）を検出してください。
検出対象:
- 氏名（漢字・カナ）
- 電話番号
- メールアドレス
- 住所
- 生年月日
- 年齢
- 患者ID・カルテ番号
- マイナンバー
- その他の識別子

テキスト:
```
{text}
```

以下のJSON形式で回答してください（説明は不要、JSONのみ）:
[
  {{"type": "NAME", "value": "検出した値", "confidence": "high/medium/low"}},
  ...
]

PIIが見つからない場合は空の配列 [] を返してください。"""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
            response_text = response["message"]["content"]

            # JSONを抽出
            json_match = self._extract_json(response_text)
            if json_match:
                return json.loads(json_match)
            return []
        except Exception:
            return []

    def _extract_json(self, text: str) -> str | None:
        """テキストからJSON配列を抽出"""
        # コードブロック内のJSON
        import re
        code_block = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
        if code_block:
            return code_block.group(1).strip()

        # 直接JSON配列
        json_match = re.search(r'\[[\s\S]*\]', text)
        if json_match:
            return json_match.group(0)

        return None

    def detect_pii_in_dataframe(self, df, sample_size: int = 5) -> dict[str, list[dict]]:
        """
        DataFrameの各列からPIIを検出する（LLMベース）

        Args:
            df: 検査対象のDataFrame
            sample_size: 各列からサンプリングする行数

        Returns:
            列名をキー、検出結果リストを値とする辞書
        """
        results = {}

        for col in df.columns:
            # サンプル値を取得
            sample_values = df[col].dropna().head(sample_size).astype(str).tolist()
            if not sample_values:
                continue

            # サンプル値を結合してLLMに渡す
            sample_text = f"列名: {col}\n値のサンプル:\n" + "\n".join(
                f"- {v}" for v in sample_values
            )

            pii_detected = self.detect_pii(sample_text)
            if pii_detected:
                results[col] = pii_detected

        return results

    def _build_messages(self) -> list[dict]:
        """送信用メッセージリストを構築"""
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.extend(self.messages)
        return messages

    def chat(self, message: str) -> str:
        """LLMとチャットする"""
        # ユーザーメッセージを追加
        self.messages.append({"role": "user", "content": message})

        # メッセージリストを構築
        messages_to_send = self._build_messages()

        # 通常モード
        response = ollama.chat(
            model=self.model,
            messages=messages_to_send,
        )
        response_text = response["message"]["content"]

        # アシスタントの応答を履歴に追加
        self.messages.append({"role": "assistant", "content": response_text})

        return response_text

    def chat_stream(self, message: str) -> Generator[str, None, None]:
        """ストリーミングでチャットする（ジェネレータを返す）"""
        # ユーザーメッセージを追加
        self.messages.append({"role": "user", "content": message})

        # メッセージリストを構築
        messages_to_send = self._build_messages()

        # ストリーミングモード
        response_text = ""
        for chunk in ollama.chat(
            model=self.model,
            messages=messages_to_send,
            stream=True,
        ):
            content = chunk.get("message", {}).get("content", "")
            response_text += content
            yield content

        # アシスタントの応答を履歴に追加
        self.messages.append({"role": "assistant", "content": response_text})
