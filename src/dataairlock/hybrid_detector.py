"""ハイブリッドPII検出器

ルールベース（正規表現）とLLMを組み合わせたPII検出を提供します。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

import pandas as pd

from .anonymizer import (
    PIIColumnResult,
    PIIDetector,
    PIIType,
    Confidence,
)
from .llm_client import (
    LLMClient,
    is_ollama_running,
    is_ollama_installed,
    start_ollama_server,
    get_available_models,
    pull_model,
    OLLAMA_AVAILABLE,
)


class DetectionMode(Enum):
    """検出モード"""
    RULE_ONLY = "rule_only"      # ルールベースのみ
    LLM_ONLY = "llm_only"        # LLMのみ
    HYBRID = "hybrid"            # ルール + LLM（推奨）


# LLMの検出タイプとPIITypeのマッピング
LLM_TYPE_TO_PII_TYPE = {
    "NAME": PIIType.NAME,
    "NAME_KANA": PIIType.NAME_KANA,
    "PHONE": PIIType.PHONE,
    "EMAIL": PIIType.EMAIL,
    "ADDRESS": PIIType.ADDRESS,
    "BIRTHDATE": PIIType.BIRTHDATE,
    "AGE": PIIType.AGE,
    "PATIENT_ID": PIIType.PATIENT_ID,
    "MY_NUMBER": PIIType.MY_NUMBER,
    # 別名のマッピング
    "氏名": PIIType.NAME,
    "電話番号": PIIType.PHONE,
    "メールアドレス": PIIType.EMAIL,
    "住所": PIIType.ADDRESS,
    "生年月日": PIIType.BIRTHDATE,
    "年齢": PIIType.AGE,
    "患者ID": PIIType.PATIENT_ID,
    "マイナンバー": PIIType.MY_NUMBER,
}


@dataclass
class HybridDetectionResult:
    """ハイブリッド検出結果"""
    column_name: str
    pii_type: PIIType
    confidence: Confidence
    detected_by: str  # "rule", "llm", "both"
    sample_values: list[str] = field(default_factory=list)
    llm_details: list[dict] = field(default_factory=list)


class OllamaSetupStatus(Enum):
    """Ollamaセットアップ状態"""
    NOT_INSTALLED = "not_installed"
    NOT_RUNNING = "not_running"
    NO_MODEL = "no_model"
    READY = "ready"


def check_ollama_status(required_model: str = "llama3.1:8b") -> OllamaSetupStatus:
    """Ollamaの状態をチェック"""
    if not is_ollama_installed():
        return OllamaSetupStatus.NOT_INSTALLED

    if not is_ollama_running():
        return OllamaSetupStatus.NOT_RUNNING

    models = get_available_models()
    # モデル名の部分一致チェック（llama3.1:8b と llama3.1:8b-instruct-q4_0 など）
    model_base = required_model.split(":")[0]
    if not any(model_base in m for m in models):
        return OllamaSetupStatus.NO_MODEL

    return OllamaSetupStatus.READY


class HybridPIIDetector:
    """ハイブリッドPII検出器"""

    def __init__(
        self,
        mode: DetectionMode = DetectionMode.HYBRID,
        llm_model: str = "llama3.1:8b",
    ):
        self.mode = mode
        self.llm_model = llm_model
        self.rule_detector = PIIDetector()
        self._llm_client: LLMClient | None = None

    @property
    def llm_client(self) -> LLMClient | None:
        """LLMクライアントを遅延初期化"""
        if self._llm_client is None and self.mode != DetectionMode.RULE_ONLY:
            if is_ollama_running():
                self._llm_client = LLMClient(model=self.llm_model)
        return self._llm_client

    def can_use_llm(self) -> bool:
        """LLMが使用可能かどうか"""
        return check_ollama_status(self.llm_model) == OllamaSetupStatus.READY

    def detect_pii_columns(
        self,
        df: pd.DataFrame,
        use_llm_fallback: bool = True,
    ) -> dict[str, HybridDetectionResult]:
        """
        DataFrameの列からPIIを検出する（ハイブリッド方式）

        Args:
            df: 検査対象のDataFrame
            use_llm_fallback: ルールで検出できない列にLLMを使用

        Returns:
            列名をキー、HybridDetectionResultを値とする辞書
        """
        results: dict[str, HybridDetectionResult] = {}

        # 1. ルールベース検出
        if self.mode in (DetectionMode.RULE_ONLY, DetectionMode.HYBRID):
            rule_results = self.rule_detector.detect_pii_columns(df)
            for col_name, pii_result in rule_results.items():
                results[col_name] = HybridDetectionResult(
                    column_name=col_name,
                    pii_type=pii_result.pii_type,
                    confidence=pii_result.confidence,
                    detected_by="rule",
                    sample_values=pii_result.sample_values,
                )

        # 2. LLM検出
        if self.mode in (DetectionMode.LLM_ONLY, DetectionMode.HYBRID):
            if self.llm_client:
                llm_results = self.llm_client.detect_pii_in_dataframe(df)
                for col_name, detections in llm_results.items():
                    if col_name in results:
                        # ルールでも検出された → 確度を上げる
                        results[col_name].detected_by = "both"
                        results[col_name].llm_details = detections
                        # LLMの確度が高ければ採用
                        if any(d.get("confidence") == "high" for d in detections):
                            results[col_name].confidence = Confidence.HIGH
                    elif use_llm_fallback or self.mode == DetectionMode.LLM_ONLY:
                        # ルールでは検出されなかったがLLMで検出
                        pii_type = self._llm_type_to_pii_type(detections)
                        confidence = self._llm_confidence_to_confidence(detections)
                        sample_values = self._get_sample_values(df[col_name])
                        results[col_name] = HybridDetectionResult(
                            column_name=col_name,
                            pii_type=pii_type,
                            confidence=confidence,
                            detected_by="llm",
                            sample_values=sample_values,
                            llm_details=detections,
                        )

        return results

    def _llm_type_to_pii_type(self, detections: list[dict]) -> PIIType:
        """LLMの検出タイプをPIITypeに変換"""
        for detection in detections:
            llm_type = detection.get("type", "").upper()
            if llm_type in LLM_TYPE_TO_PII_TYPE:
                return LLM_TYPE_TO_PII_TYPE[llm_type]
        return PIIType.UNKNOWN

    def _llm_confidence_to_confidence(self, detections: list[dict]) -> Confidence:
        """LLMの確度をConfidenceに変換"""
        confidences = [d.get("confidence", "").lower() for d in detections]
        if "high" in confidences:
            return Confidence.HIGH
        elif "medium" in confidences:
            return Confidence.MEDIUM
        return Confidence.LOW

    def _get_sample_values(self, series: pd.Series, max_samples: int = 10) -> list[str]:
        """列からサンプル値を取得"""
        non_null = series.dropna().astype(str)
        unique_values = non_null.unique()
        return list(unique_values[:max_samples])

    def to_pii_column_results(
        self,
        hybrid_results: dict[str, HybridDetectionResult],
    ) -> dict[str, PIIColumnResult]:
        """HybridDetectionResultをPIIColumnResultに変換（既存APIとの互換性）"""
        return {
            col_name: PIIColumnResult(
                column_name=result.column_name,
                pii_type=result.pii_type,
                confidence=result.confidence,
                matched_by=result.detected_by,
                sample_values=result.sample_values,
            )
            for col_name, result in hybrid_results.items()
        }


def setup_ollama_interactive(
    required_model: str = "llama3.1:8b",
) -> tuple[bool, str]:
    """
    Ollamaの対話的セットアップ（TUI/CLI用のヘルパー）

    Returns:
        (成功したか, メッセージ)
    """
    status = check_ollama_status(required_model)

    if status == OllamaSetupStatus.READY:
        return True, "Ollamaは使用可能です"

    if status == OllamaSetupStatus.NOT_INSTALLED:
        from .llm_client import get_ollama_install_instructions
        return False, f"Ollamaがインストールされていません。\n{get_ollama_install_instructions()}"

    if status == OllamaSetupStatus.NOT_RUNNING:
        # サーバー起動を試みる
        if start_ollama_server():
            # 再チェック
            if check_ollama_status(required_model) == OllamaSetupStatus.READY:
                return True, "Ollamaサーバーを起動しました"
            # モデルがない場合は次のチェックへ
            status = OllamaSetupStatus.NO_MODEL
        else:
            return False, "Ollamaサーバーの起動に失敗しました。手動で 'ollama serve' を実行してください。"

    if status == OllamaSetupStatus.NO_MODEL:
        return False, f"モデル '{required_model}' がありません。'ollama pull {required_model}' でダウンロードしてください。"

    return False, "不明なエラー"


# 便利関数
def detect_pii_hybrid(
    df: pd.DataFrame,
    mode: DetectionMode = DetectionMode.HYBRID,
    llm_model: str = "llama3.1:8b",
) -> dict[str, PIIColumnResult]:
    """
    ハイブリッド方式でPII検出（便利関数）

    Args:
        df: 検査対象のDataFrame
        mode: 検出モード
        llm_model: 使用するLLMモデル

    Returns:
        列名をキー、PIIColumnResultを値とする辞書
    """
    detector = HybridPIIDetector(mode=mode, llm_model=llm_model)
    hybrid_results = detector.detect_pii_columns(df)
    return detector.to_pii_column_results(hybrid_results)
