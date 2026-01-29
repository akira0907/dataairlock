"""Ollama ローカルLLM連携"""

from typing import Optional, Generator

import ollama


class LLMClient:
    """Ollamaを使ったローカルLLMクライアント"""

    def __init__(self, model: str = "llama3.1:8b"):
        self.model = model
        self.messages: list[dict] = []
        self.system_prompt: Optional[str] = None

    def set_system_prompt(self, prompt: str) -> None:
        """システムプロンプトを設定"""
        self.system_prompt = prompt

    def reset(self) -> None:
        """会話履歴をリセット"""
        self.messages = []

    def detect_pii(self, text: str) -> list[dict]:
        """テキストから個人情報を検出する"""
        # TODO: PII検出ロジックを実装
        raise NotImplementedError

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
