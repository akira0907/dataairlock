"""ハイブリッドPII検出器のテスト"""

import pytest
import pandas as pd
from unittest.mock import patch, MagicMock

from dataairlock.hybrid_detector import (
    HybridPIIDetector,
    HybridDetectionResult,
    DetectionMode,
    OllamaSetupStatus,
    check_ollama_status,
    setup_ollama_interactive,
    detect_pii_hybrid,
    LLM_TYPE_TO_PII_TYPE,
)
from dataairlock.anonymizer import PIIType, Confidence, PIIColumnResult


class TestDetectionMode:
    """DetectionMode のテスト"""

    def test_detection_modes(self):
        """検出モードの定義"""
        assert DetectionMode.RULE_ONLY.value == "rule_only"
        assert DetectionMode.LLM_ONLY.value == "llm_only"
        assert DetectionMode.HYBRID.value == "hybrid"


class TestOllamaSetupStatus:
    """OllamaSetupStatus のテスト"""

    def test_setup_status(self):
        """セットアップ状態の定義"""
        assert OllamaSetupStatus.NOT_INSTALLED.value == "not_installed"
        assert OllamaSetupStatus.NOT_RUNNING.value == "not_running"
        assert OllamaSetupStatus.NO_MODEL.value == "no_model"
        assert OllamaSetupStatus.READY.value == "ready"


class TestCheckOllamaStatus:
    """check_ollama_status のテスト"""

    @patch("dataairlock.hybrid_detector.is_ollama_installed")
    def test_not_installed(self, mock_installed):
        """Ollamaがインストールされていない場合"""
        mock_installed.return_value = False
        assert check_ollama_status() == OllamaSetupStatus.NOT_INSTALLED

    @patch("dataairlock.hybrid_detector.is_ollama_installed")
    @patch("dataairlock.hybrid_detector.is_ollama_running")
    def test_not_running(self, mock_running, mock_installed):
        """Ollamaが起動していない場合"""
        mock_installed.return_value = True
        mock_running.return_value = False
        assert check_ollama_status() == OllamaSetupStatus.NOT_RUNNING

    @patch("dataairlock.hybrid_detector.is_ollama_installed")
    @patch("dataairlock.hybrid_detector.is_ollama_running")
    @patch("dataairlock.hybrid_detector.get_available_models")
    def test_no_model(self, mock_models, mock_running, mock_installed):
        """必要なモデルがない場合"""
        mock_installed.return_value = True
        mock_running.return_value = True
        mock_models.return_value = ["other-model"]
        assert check_ollama_status("llama3.1:8b") == OllamaSetupStatus.NO_MODEL

    @patch("dataairlock.hybrid_detector.is_ollama_installed")
    @patch("dataairlock.hybrid_detector.is_ollama_running")
    @patch("dataairlock.hybrid_detector.get_available_models")
    def test_ready(self, mock_models, mock_running, mock_installed):
        """準備完了の場合"""
        mock_installed.return_value = True
        mock_running.return_value = True
        mock_models.return_value = ["llama3.1:8b", "other-model"]
        assert check_ollama_status("llama3.1:8b") == OllamaSetupStatus.READY


class TestHybridPIIDetector:
    """HybridPIIDetector のテスト"""

    def test_init_rule_only(self):
        """ルールベースモードでの初期化"""
        detector = HybridPIIDetector(mode=DetectionMode.RULE_ONLY)
        assert detector.mode == DetectionMode.RULE_ONLY
        assert detector.rule_detector is not None

    def test_init_hybrid(self):
        """ハイブリッドモードでの初期化"""
        detector = HybridPIIDetector(mode=DetectionMode.HYBRID)
        assert detector.mode == DetectionMode.HYBRID

    @patch("dataairlock.hybrid_detector.is_ollama_running")
    def test_can_use_llm_not_available(self, mock_running):
        """LLMが使用不可の場合"""
        mock_running.return_value = False
        detector = HybridPIIDetector(mode=DetectionMode.HYBRID)
        assert not detector.can_use_llm()

    def test_detect_rule_only_with_pii(self):
        """ルールベースモードでのPII検出（PIIあり）"""
        detector = HybridPIIDetector(mode=DetectionMode.RULE_ONLY)
        df = pd.DataFrame({
            "氏名": ["山田太郎", "田中花子"],
            "電話番号": ["090-1234-5678", "080-9876-5432"],
            "備考": ["メモ1", "メモ2"],
        })

        results = detector.detect_pii_columns(df)

        assert "氏名" in results
        assert results["氏名"].pii_type == PIIType.NAME
        assert results["氏名"].detected_by == "rule"

        assert "電話番号" in results
        assert results["電話番号"].pii_type == PIIType.PHONE

        assert "備考" not in results

    def test_detect_rule_only_no_pii(self):
        """ルールベースモードでのPII検出（PIIなし）"""
        detector = HybridPIIDetector(mode=DetectionMode.RULE_ONLY)
        df = pd.DataFrame({
            "商品名": ["りんご", "みかん"],
            "価格": [100, 200],
        })

        results = detector.detect_pii_columns(df)

        assert len(results) == 0

    def test_to_pii_column_results(self):
        """PIIColumnResultへの変換"""
        detector = HybridPIIDetector(mode=DetectionMode.RULE_ONLY)

        hybrid_results = {
            "氏名": HybridDetectionResult(
                column_name="氏名",
                pii_type=PIIType.NAME,
                confidence=Confidence.HIGH,
                detected_by="rule",
                sample_values=["山田太郎"],
            ),
        }

        pii_results = detector.to_pii_column_results(hybrid_results)

        assert "氏名" in pii_results
        assert isinstance(pii_results["氏名"], PIIColumnResult)
        assert pii_results["氏名"].pii_type == PIIType.NAME
        assert pii_results["氏名"].confidence == Confidence.HIGH


class TestLLMTypeToPIIType:
    """LLM_TYPE_TO_PII_TYPE マッピングのテスト"""

    def test_english_mappings(self):
        """英語タイプのマッピング"""
        assert LLM_TYPE_TO_PII_TYPE["NAME"] == PIIType.NAME
        assert LLM_TYPE_TO_PII_TYPE["PHONE"] == PIIType.PHONE
        assert LLM_TYPE_TO_PII_TYPE["EMAIL"] == PIIType.EMAIL
        assert LLM_TYPE_TO_PII_TYPE["ADDRESS"] == PIIType.ADDRESS

    def test_japanese_mappings(self):
        """日本語タイプのマッピング"""
        assert LLM_TYPE_TO_PII_TYPE["氏名"] == PIIType.NAME
        assert LLM_TYPE_TO_PII_TYPE["電話番号"] == PIIType.PHONE
        assert LLM_TYPE_TO_PII_TYPE["メールアドレス"] == PIIType.EMAIL
        assert LLM_TYPE_TO_PII_TYPE["住所"] == PIIType.ADDRESS


class TestDetectPIIHybrid:
    """detect_pii_hybrid 便利関数のテスト"""

    def test_detect_pii_hybrid_rule_only(self):
        """ルールベースモードでの便利関数"""
        df = pd.DataFrame({
            "氏名": ["山田太郎", "田中花子"],
            "電話番号": ["090-1234-5678", "080-9876-5432"],
        })

        results = detect_pii_hybrid(df, mode=DetectionMode.RULE_ONLY)

        assert "氏名" in results
        assert isinstance(results["氏名"], PIIColumnResult)
        assert results["氏名"].pii_type == PIIType.NAME


class TestHybridDetectionResult:
    """HybridDetectionResult のテスト"""

    def test_create_result(self):
        """結果オブジェクトの作成"""
        result = HybridDetectionResult(
            column_name="氏名",
            pii_type=PIIType.NAME,
            confidence=Confidence.HIGH,
            detected_by="rule",
            sample_values=["山田太郎"],
            llm_details=[],
        )

        assert result.column_name == "氏名"
        assert result.pii_type == PIIType.NAME
        assert result.confidence == Confidence.HIGH
        assert result.detected_by == "rule"
        assert result.sample_values == ["山田太郎"]
        assert result.llm_details == []

    def test_default_values(self):
        """デフォルト値"""
        result = HybridDetectionResult(
            column_name="test",
            pii_type=PIIType.UNKNOWN,
            confidence=Confidence.LOW,
            detected_by="llm",
        )

        assert result.sample_values == []
        assert result.llm_details == []
