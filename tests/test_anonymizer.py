"""Anonymizer テスト"""

import tempfile
from pathlib import Path

import pandas as pd
import pytest

from dataairlock.anonymizer import (
    Anonymizer,
    Confidence,
    PIIDetector,
    PIIType,
    anonymize_dataframe,
    deanonymize_dataframe,
    detect_pii_columns,
    detect_pii_values,
    load_mapping,
    save_mapping,
)


class TestPIIDetector:
    """PIIDetectorのテスト"""

    @pytest.fixture
    def detector(self):
        return PIIDetector()

    @pytest.fixture
    def sample_df(self):
        """医療機関向けサンプルデータ"""
        return pd.DataFrame({
            "患者ID": ["P001", "P002", "P003"],
            "氏名": ["山田太郎", "鈴木花子", "佐藤一郎"],
            "カナ": ["ヤマダタロウ", "スズキハナコ", "サトウイチロウ"],
            "生年月日": ["1990/01/15", "1985/03/20", "1978/12/01"],
            "年齢": ["34歳", "39歳", "46歳"],
            "電話番号": ["03-1234-5678", "090-1234-5678", "06-9876-5432"],
            "メールアドレス": ["yamada@example.com", "suzuki@example.com", "sato@example.com"],
            "住所": ["東京都新宿区西新宿1-1-1", "大阪府大阪市北区梅田2-2-2", "北海道札幌市中央区大通3-3-3"],
            "診断コード": ["A001", "B002", "C003"],  # PII以外の列
        })

    def test_detect_column_by_name_patient_id(self, detector):
        """患者ID列名の検出"""
        df = pd.DataFrame({"患者ID": ["P001", "P002"]})
        results = detector.detect_pii_columns(df)

        assert "患者ID" in results
        assert results["患者ID"].pii_type == PIIType.PATIENT_ID
        assert results["患者ID"].confidence == Confidence.HIGH
        assert results["患者ID"].matched_by == "column_name"

    def test_detect_column_by_name_name(self, detector):
        """氏名列名の検出"""
        df = pd.DataFrame({"氏名": ["山田太郎", "鈴木花子"]})
        results = detector.detect_pii_columns(df)

        assert "氏名" in results
        assert results["氏名"].pii_type == PIIType.NAME
        assert results["氏名"].confidence == Confidence.HIGH

    def test_detect_column_by_name_kana(self, detector):
        """カナ列名の検出"""
        df = pd.DataFrame({"フリガナ": ["ヤマダタロウ", "スズキハナコ"]})
        results = detector.detect_pii_columns(df)

        assert "フリガナ" in results
        assert results["フリガナ"].pii_type == PIIType.NAME_KANA

    def test_detect_column_by_name_birthdate(self, detector):
        """生年月日列名の検出"""
        df = pd.DataFrame({"生年月日": ["1990/01/15", "1985/03/20"]})
        results = detector.detect_pii_columns(df)

        assert "生年月日" in results
        assert results["生年月日"].pii_type == PIIType.BIRTHDATE

    def test_detect_column_by_name_phone(self, detector):
        """電話番号列名の検出"""
        for col_name in ["電話番号", "TEL", "携帯番号", "緊急連絡先"]:
            df = pd.DataFrame({col_name: ["03-1234-5678"]})
            results = detector.detect_pii_columns(df)
            assert col_name in results
            assert results[col_name].pii_type == PIIType.PHONE

    def test_detect_column_by_name_email(self, detector):
        """メール列名の検出"""
        df = pd.DataFrame({"メールアドレス": ["test@example.com"]})
        results = detector.detect_pii_columns(df)

        assert "メールアドレス" in results
        assert results["メールアドレス"].pii_type == PIIType.EMAIL

    def test_detect_column_by_name_address(self, detector):
        """住所列名の検出"""
        df = pd.DataFrame({"住所": ["東京都新宿区"]})
        results = detector.detect_pii_columns(df)

        assert "住所" in results
        assert results["住所"].pii_type == PIIType.ADDRESS

    def test_detect_column_by_name_mynumber(self, detector):
        """マイナンバー列名の検出"""
        df = pd.DataFrame({"マイナンバー": ["123456789012"]})
        results = detector.detect_pii_columns(df)

        assert "マイナンバー" in results
        assert results["マイナンバー"].pii_type == PIIType.MY_NUMBER

    def test_detect_column_by_content_phone(self, detector):
        """データ内容から電話番号を検出"""
        df = pd.DataFrame({"contact": ["03-1234-5678", "090-1111-2222", "06-9999-8888"]})
        results = detector.detect_pii_columns(df)

        assert "contact" in results
        assert results["contact"].pii_type == PIIType.PHONE
        assert results["contact"].matched_by == "content"

    def test_detect_column_by_content_email(self, detector):
        """データ内容からメールを検出"""
        df = pd.DataFrame({"連絡情報": ["a@example.com", "b@example.com", "c@example.com"]})
        results = detector.detect_pii_columns(df)

        assert "連絡情報" in results
        assert results["連絡情報"].pii_type == PIIType.EMAIL

    def test_detect_column_by_content_birthdate(self, detector):
        """データ内容から生年月日を検出"""
        df = pd.DataFrame({"date_field": ["1990/01/15", "1985/03/20", "1978/12/01"]})
        results = detector.detect_pii_columns(df)

        assert "date_field" in results
        assert results["date_field"].pii_type == PIIType.BIRTHDATE

    def test_detect_all_pii_columns(self, detector, sample_df):
        """サンプルデータで全PII列を検出"""
        results = detector.detect_pii_columns(sample_df)

        # 検出されるべき列
        assert "患者ID" in results
        assert "氏名" in results
        assert "カナ" in results
        assert "生年月日" in results
        assert "年齢" in results
        assert "電話番号" in results
        assert "メールアドレス" in results
        assert "住所" in results

        # 検出されるべきでない列
        assert "診断コード" not in results

    def test_detect_pii_values_phone(self, detector):
        """セル単位で電話番号を検出"""
        series = pd.Series(["連絡先: 03-1234-5678", "携帯: 090-1111-2222"])
        results = detector.detect_pii_values(series)

        assert len(results) == 2
        assert len(results[0]) == 1
        assert results[0][0].pii_type == PIIType.PHONE
        assert results[0][0].value == "03-1234-5678"

    def test_detect_pii_values_email(self, detector):
        """セル単位でメールを検出"""
        series = pd.Series(["送信先: test@example.com"])
        results = detector.detect_pii_values(series)

        assert len(results[0]) == 1
        assert results[0][0].pii_type == PIIType.EMAIL
        assert results[0][0].value == "test@example.com"

    def test_detect_pii_values_multiple(self, detector):
        """1セルに複数のPIIを検出"""
        series = pd.Series(["電話03-1234-5678 メールtest@example.com"])
        results = detector.detect_pii_values(series)

        assert len(results[0]) == 2
        pii_types = {r.pii_type for r in results[0]}
        assert PIIType.PHONE in pii_types
        assert PIIType.EMAIL in pii_types

    def test_detect_pii_values_birthdate_western(self, detector):
        """西暦生年月日を検出"""
        series = pd.Series(["生年月日: 1990/01/15"])
        results = detector.detect_pii_values(series)

        assert len(results[0]) == 1
        assert results[0][0].pii_type == PIIType.BIRTHDATE

    def test_detect_pii_values_birthdate_japanese(self, detector):
        """和暦生年月日を検出"""
        series = pd.Series(["昭和65年01月15日生まれ"])
        results = detector.detect_pii_values(series)

        assert len(results[0]) == 1
        assert results[0][0].pii_type == PIIType.BIRTHDATE

    def test_detect_pii_values_address(self, detector):
        """住所を検出"""
        series = pd.Series(["東京都新宿区西新宿1-1-1"])
        results = detector.detect_pii_values(series)

        assert len(results[0]) >= 1
        assert any(r.pii_type == PIIType.ADDRESS for r in results[0])

    def test_detect_pii_values_postal_code(self, detector):
        """郵便番号を検出"""
        series = pd.Series(["〒160-0023"])
        results = detector.detect_pii_values(series)

        assert len(results[0]) == 1
        assert results[0][0].pii_type == PIIType.ADDRESS
        assert results[0][0].value == "160-0023"

    def test_detect_pii_values_age(self, detector):
        """年齢を検出"""
        series = pd.Series(["患者は35歳の男性"])
        results = detector.detect_pii_values(series)

        assert len(results[0]) == 1
        assert results[0][0].pii_type == PIIType.AGE
        assert results[0][0].value == "35歳"


class TestConvenienceFunctions:
    """便利関数のテスト"""

    def test_detect_pii_columns_function(self):
        """detect_pii_columns便利関数"""
        df = pd.DataFrame({"患者ID": ["P001"], "氏名": ["山田太郎"]})
        results = detect_pii_columns(df)

        assert "患者ID" in results
        assert "氏名" in results

    def test_detect_pii_values_function(self):
        """detect_pii_values便利関数"""
        series = pd.Series(["03-1234-5678"])
        results = detect_pii_values(series)

        assert len(results[0]) == 1
        assert results[0][0].pii_type == PIIType.PHONE


class TestAnonymizeDataframe:
    """anonymize_dataframe関数のテスト"""

    @pytest.fixture
    def sample_df(self):
        return pd.DataFrame({
            "患者ID": ["P001", "P002", "P003"],
            "氏名": ["山田太郎", "鈴木花子", "佐藤一郎"],
            "生年月日": ["1990/01/15", "1985/03/20", "1978/12/01"],
            "年齢": ["34歳", "39歳", "46歳"],
            "住所": ["東京都新宿区西新宿1-1-1", "大阪府大阪市北区梅田2-2-2", "北海道札幌市中央区大通3-3-3"],
            "診断コード": ["A001", "B002", "C003"],
        })

    @pytest.fixture
    def pii_columns(self, sample_df):
        return detect_pii_columns(sample_df)

    def test_replace_strategy(self, sample_df, pii_columns):
        """replace戦略のテスト"""
        anon_df, mapping = anonymize_dataframe(sample_df, pii_columns, strategy="replace")

        # 元の値が置換されている
        assert anon_df["患者ID"].iloc[0] != "P001"
        assert anon_df["患者ID"].iloc[0].startswith("ANON_")

        # 診断コードは変更されていない
        assert anon_df["診断コード"].iloc[0] == "A001"

        # マッピングにメタデータがある
        assert "metadata" in mapping
        assert mapping["metadata"]["strategy"] == "replace"

        # マッピングに列情報がある
        assert "患者ID" in mapping
        assert mapping["患者ID"]["action"] == "replaced"

    def test_generalize_strategy_birthdate(self, sample_df, pii_columns):
        """generalize戦略: 生年月日→年代"""
        anon_df, mapping = anonymize_dataframe(sample_df, pii_columns, strategy="generalize")

        # 生年月日が年代に一般化されている
        assert anon_df["生年月日"].iloc[0] == "1990年代"
        assert anon_df["生年月日"].iloc[1] == "1980年代"
        assert anon_df["生年月日"].iloc[2] == "1970年代"

    def test_generalize_strategy_address(self, sample_df, pii_columns):
        """generalize戦略: 住所→都道府県"""
        anon_df, mapping = anonymize_dataframe(sample_df, pii_columns, strategy="generalize")

        # 住所が都道府県のみに一般化されている
        assert anon_df["住所"].iloc[0] == "東京都"
        assert anon_df["住所"].iloc[1] == "大阪府"
        assert anon_df["住所"].iloc[2] == "北海道"

    def test_generalize_strategy_age(self, sample_df, pii_columns):
        """generalize戦略: 年齢→年代"""
        anon_df, mapping = anonymize_dataframe(sample_df, pii_columns, strategy="generalize")

        # 年齢が年代に一般化されている
        assert anon_df["年齢"].iloc[0] == "30代"
        assert anon_df["年齢"].iloc[1] == "30代"
        assert anon_df["年齢"].iloc[2] == "40代"

    def test_delete_strategy(self, sample_df, pii_columns):
        """delete戦略のテスト"""
        anon_df, mapping = anonymize_dataframe(sample_df, pii_columns, strategy="delete")

        # PII列が削除されている
        assert "患者ID" not in anon_df.columns
        assert "氏名" not in anon_df.columns

        # 診断コードは残っている
        assert "診断コード" in anon_df.columns

        # マッピングに削除情報がある
        assert mapping["患者ID"]["action"] == "deleted"

    def test_mapping_metadata(self, sample_df, pii_columns):
        """マッピングのメタデータ"""
        _, mapping = anonymize_dataframe(
            sample_df, pii_columns, strategy="replace", original_file="test.csv"
        )

        assert "metadata" in mapping
        assert "created_at" in mapping["metadata"]
        assert mapping["metadata"]["strategy"] == "replace"
        assert mapping["metadata"]["original_file"] == "test.csv"
        assert "columns_processed" in mapping["metadata"]


class TestDeanonymizeDataframe:
    """deanonymize_dataframe関数のテスト"""

    def test_deanonymize_replace(self):
        """replace戦略の復元"""
        original_df = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
        })
        pii_columns = detect_pii_columns(original_df)

        # 匿名化
        anon_df, mapping = anonymize_dataframe(original_df, pii_columns, strategy="replace")

        # 復元
        restored_df = deanonymize_dataframe(anon_df, mapping)

        # 元の値に戻っている
        assert restored_df["患者ID"].iloc[0] == "P001"
        assert restored_df["氏名"].iloc[0] == "山田太郎"

    def test_deanonymize_generalize(self):
        """generalize戦略の復元"""
        original_df = pd.DataFrame({
            "住所": ["東京都新宿区西新宿1-1-1"],
        })
        pii_columns = detect_pii_columns(original_df)

        # 匿名化
        anon_df, mapping = anonymize_dataframe(original_df, pii_columns, strategy="generalize")

        # 復元
        restored_df = deanonymize_dataframe(anon_df, mapping)

        # 元の値に戻っている
        assert restored_df["住所"].iloc[0] == "東京都新宿区西新宿1-1-1"


class TestMappingPersistence:
    """マッピング保存・読み込みのテスト"""

    def test_save_and_load_mapping(self):
        """マッピングの保存と読み込み"""
        mapping = {
            "患者ID": {
                "action": "replaced",
                "pii_type": "患者ID",
                "values": {"P001": "ANON_12345678"},
            },
            "metadata": {
                "created_at": "2024-01-01T00:00:00",
                "strategy": "replace",
            },
        }
        password = "test_password_123"

        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as f:
            filepath = Path(f.name)

        try:
            # 保存
            save_mapping(mapping, filepath, password)

            # ファイルが存在する
            assert filepath.exists()

            # 読み込み
            loaded = load_mapping(filepath, password)

            # 内容が一致
            assert loaded == mapping
        finally:
            filepath.unlink()

    def test_load_with_wrong_password(self):
        """間違ったパスワードでの読み込み"""
        mapping = {"test": "data"}
        password = "correct_password"
        wrong_password = "wrong_password"

        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as f:
            filepath = Path(f.name)

        try:
            save_mapping(mapping, filepath, password)

            with pytest.raises(ValueError, match="パスワードが正しくない"):
                load_mapping(filepath, wrong_password)
        finally:
            filepath.unlink()

    def test_mapping_contains_japanese(self):
        """日本語を含むマッピングの保存・読み込み"""
        mapping = {
            "氏名": {
                "values": {"山田太郎": "ANON_XXXXXXXX", "鈴木花子": "ANON_YYYYYYYY"},
            },
        }
        password = "日本語パスワード"

        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as f:
            filepath = Path(f.name)

        try:
            save_mapping(mapping, filepath, password)
            loaded = load_mapping(filepath, password)
            assert loaded == mapping
        finally:
            filepath.unlink()


class TestAnonymizer:
    """Anonymizerクラスのテスト"""

    def test_init(self):
        anonymizer = Anonymizer()
        assert anonymizer.mappings == {}
        assert anonymizer.detector is not None

    def test_anonymize_auto_detect(self):
        """自動検出による匿名化"""
        anonymizer = Anonymizer()
        df = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
            "診断コード": ["A001", "B002"],
        })

        anon_df, mapping = anonymizer.anonymize(df)

        # PII列が匿名化されている
        assert anon_df["患者ID"].iloc[0].startswith("ANON_")
        assert anon_df["氏名"].iloc[0].startswith("ANON_")

        # 非PII列は変更されていない
        assert anon_df["診断コード"].iloc[0] == "A001"

    def test_anonymize_manual_columns(self):
        """手動指定による匿名化"""
        anonymizer = Anonymizer()
        df = pd.DataFrame({
            "custom_id": ["ID001", "ID002"],
            "secret_data": ["秘密1", "秘密2"],
            "public_data": ["公開1", "公開2"],
        })

        anon_df, mapping = anonymizer.anonymize(df, columns=["custom_id", "secret_data"])

        # 指定列が匿名化されている
        assert anon_df["custom_id"].iloc[0].startswith("ANON_")
        assert anon_df["secret_data"].iloc[0].startswith("ANON_")

        # 非指定列は変更されていない
        assert anon_df["public_data"].iloc[0] == "公開1"

    def test_anonymize_with_strategy(self):
        """戦略指定による匿名化"""
        anonymizer = Anonymizer()
        df = pd.DataFrame({
            "住所": ["東京都新宿区西新宿1-1-1"],
        })

        anon_df, _ = anonymizer.anonymize(df, strategy="generalize")

        assert anon_df["住所"].iloc[0] == "東京都"

    def test_deanonymize(self):
        """Anonymizerクラスによる復元"""
        anonymizer = Anonymizer()
        df = pd.DataFrame({
            "患者ID": ["P001"],
            "氏名": ["山田太郎"],
        })

        anon_df, mapping = anonymizer.anonymize(df)
        restored_df = anonymizer.deanonymize(anon_df)

        assert restored_df["患者ID"].iloc[0] == "P001"
        assert restored_df["氏名"].iloc[0] == "山田太郎"
