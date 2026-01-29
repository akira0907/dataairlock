"""Ollama ローカルLLM連携"""

import ollama


class LLMClient:
    """Ollamaを使ったローカルLLMクライアント"""

    def __init__(self, model: str = "llama3.2"):
        self.model = model

    def detect_pii(self, text: str) -> list[dict]:
        """テキストから個人情報を検出する"""
        # TODO: PII検出ロジックを実装
        raise NotImplementedError

    def chat(self, message: str) -> str:
        """LLMとチャットする"""
        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": message}]
        )
        return response["message"]["content"]
