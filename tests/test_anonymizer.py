"""Anonymizer テスト"""

import re
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from dataairlock.anonymizer import (
    Anonymizer,
    Confidence,
    PIIDetector,
    PIIType,
    SEMANTIC_PREFIXES,
    anonymize_dataframe,
    check_collision,
    deanonymize_dataframe,
    detect_pii_columns,
    detect_pii_values,
    generate_session_id,
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
        # セマンティックIDが使用されている (PATIENT_XXX)
        assert anon_df["患者ID"].iloc[0].startswith("PATIENT_")

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

        # PII列がセマンティックIDで匿名化されている
        assert anon_df["患者ID"].iloc[0].startswith("PATIENT_")
        assert anon_df["氏名"].iloc[0].startswith("PERSON_")

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

        # 指定列がセマンティックIDで匿名化されている (不明な型はID_XXX)
        assert anon_df["custom_id"].iloc[0].startswith("ID_")
        assert anon_df["secret_data"].iloc[0].startswith("ID_")

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


class TestSemanticIDs:
    """セマンティックIDのテスト"""

    def test_semantic_prefixes_defined(self):
        """SEMANTIC_PREFIXESが全PIITypeに対して定義されている"""
        for pii_type in PIIType:
            assert pii_type in SEMANTIC_PREFIXES, f"{pii_type} is missing from SEMANTIC_PREFIXES"

    def test_semantic_id_format(self):
        """セマンティックIDのフォーマット（PREFIX_001_SESSION形式）"""
        df = pd.DataFrame({
            "患者ID": ["P001", "P002", "P003"],
        })
        pii_columns = detect_pii_columns(df)
        anon_df, mapping = anonymize_dataframe(df, pii_columns, strategy="replace")

        # セッションIDがメタデータに含まれている
        session_id = mapping["metadata"]["session_id"]
        assert len(session_id) == 4
        assert session_id.isupper() or session_id.isalnum()

        # 連番で生成されている（セッションIDが付加される）
        assert anon_df["患者ID"].iloc[0] == f"PATIENT_001_{session_id}"
        assert anon_df["患者ID"].iloc[1] == f"PATIENT_002_{session_id}"
        assert anon_df["患者ID"].iloc[2] == f"PATIENT_003_{session_id}"

    def test_semantic_id_same_value_same_id(self):
        """同じ値は同じIDになる"""
        df = pd.DataFrame({
            "患者ID": ["P001", "P002", "P001", "P003", "P001"],
        })
        pii_columns = detect_pii_columns(df)
        anon_df, _ = anonymize_dataframe(df, pii_columns, strategy="replace")

        # P001は全て同じID
        assert anon_df["患者ID"].iloc[0] == anon_df["患者ID"].iloc[2]
        assert anon_df["患者ID"].iloc[0] == anon_df["患者ID"].iloc[4]

        # P002, P003は異なるID
        assert anon_df["患者ID"].iloc[1] != anon_df["患者ID"].iloc[0]
        assert anon_df["患者ID"].iloc[3] != anon_df["患者ID"].iloc[0]

    def test_semantic_id_different_types(self):
        """異なるPIIタイプは異なるプレフィックスを使用"""
        df = pd.DataFrame({
            "患者ID": ["P001"],
            "氏名": ["山田太郎"],
            "電話番号": ["03-1234-5678"],
            "メールアドレス": ["test@example.com"],
        })
        pii_columns = detect_pii_columns(df)
        anon_df, _ = anonymize_dataframe(df, pii_columns, strategy="replace")

        # 各列は対応するプレフィックスを使用
        assert anon_df["患者ID"].iloc[0].startswith("PATIENT_")
        assert anon_df["氏名"].iloc[0].startswith("PERSON_")
        assert anon_df["電話番号"].iloc[0].startswith("PHONE_")
        assert anon_df["メールアドレス"].iloc[0].startswith("EMAIL_")

    def test_semantic_id_sequential_numbering(self):
        """異なる列は独立したカウンターを使用"""
        df = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
        })
        pii_columns = detect_pii_columns(df)
        anon_df, mapping = anonymize_dataframe(df, pii_columns, strategy="replace")

        session_id = mapping["metadata"]["session_id"]

        # 各列の最初の値は001（同一セッションIDが付加される）
        assert anon_df["患者ID"].iloc[0] == f"PATIENT_001_{session_id}"
        assert anon_df["氏名"].iloc[0] == f"PERSON_001_{session_id}"

    def test_semantic_id_unknown_type(self):
        """不明なPIIタイプはID_プレフィックスを使用"""
        anonymizer = Anonymizer()
        df = pd.DataFrame({
            "custom_field": ["value1", "value2"],
        })
        # 手動で列を指定（不明な型として扱われる）
        anon_df, _ = anonymizer.anonymize(df, columns=["custom_field"])

        assert anon_df["custom_field"].iloc[0].startswith("ID_")
        assert anon_df["custom_field"].iloc[1].startswith("ID_")

    def test_semantic_id_in_mapping(self):
        """マッピングにセマンティックIDが保存される"""
        df = pd.DataFrame({
            "患者ID": ["P001", "P002"],
        })
        pii_columns = detect_pii_columns(df)
        _, mapping = anonymize_dataframe(df, pii_columns, strategy="replace")

        session_id = mapping["metadata"]["session_id"]

        assert "患者ID" in mapping
        assert mapping["患者ID"]["values"]["P001"] == f"PATIENT_001_{session_id}"
        assert mapping["患者ID"]["values"]["P002"] == f"PATIENT_002_{session_id}"

    def test_semantic_id_deanonymize(self):
        """セマンティックIDから元の値を復元できる"""
        df = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
        })
        pii_columns = detect_pii_columns(df)
        anon_df, mapping = anonymize_dataframe(df, pii_columns, strategy="replace")
        restored_df = deanonymize_dataframe(anon_df, mapping)

        assert restored_df["患者ID"].iloc[0] == "P001"
        assert restored_df["患者ID"].iloc[1] == "P002"
        assert restored_df["氏名"].iloc[0] == "山田太郎"
        assert restored_df["氏名"].iloc[1] == "鈴木花子"

    def test_semantic_id_generalize_fallback(self):
        """generalize戦略のフォールバックもセマンティックIDを使用"""
        df = pd.DataFrame({
            "患者ID": ["P001", "P002"],  # generalize不可 -> セマンティックIDにフォールバック
            "住所": ["東京都新宿区", "大阪府大阪市"],  # generalize可
        })
        pii_columns = detect_pii_columns(df)
        anon_df, mapping = anonymize_dataframe(df, pii_columns, strategy="generalize")

        session_id = mapping["metadata"]["session_id"]

        # 患者IDはgeneralize不可なのでセマンティックIDにフォールバック
        assert anon_df["患者ID"].iloc[0] == f"PATIENT_001_{session_id}"

        # 住所は都道府県に一般化
        assert anon_df["住所"].iloc[0] == "東京都"
        assert anon_df["住所"].iloc[1] == "大阪府"


class TestSessionID:
    """セッションIDのテスト"""

    def test_generate_session_id_default_length(self):
        """デフォルトの長さ（4文字）のセッションID生成"""
        session_id = generate_session_id()
        assert len(session_id) == 4
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for c in session_id)

    def test_generate_session_id_custom_length(self):
        """カスタム長のセッションID生成"""
        session_id = generate_session_id(5)
        assert len(session_id) == 5

    def test_generate_session_id_uniqueness(self):
        """セッションIDの一意性（確率的テスト）"""
        ids = [generate_session_id() for _ in range(100)]
        # 100回生成してほとんどがユニークであることを確認
        assert len(set(ids)) > 90

    def test_session_id_in_metadata(self):
        """セッションIDがメタデータに含まれる"""
        df = pd.DataFrame({"患者ID": ["P001", "P002"]})
        pii_columns = detect_pii_columns(df)
        _, mapping = anonymize_dataframe(df, pii_columns, strategy="replace")

        assert "session_id" in mapping["metadata"]
        assert len(mapping["metadata"]["session_id"]) == 4

    def test_same_session_id_for_all_columns(self):
        """同一ファイル内の全列は同じセッションIDを使用"""
        df = pd.DataFrame({
            "患者ID": ["P001"],
            "氏名": ["山田太郎"],
        })
        pii_columns = detect_pii_columns(df)
        anon_df, mapping = anonymize_dataframe(df, pii_columns, strategy="replace")

        session_id = mapping["metadata"]["session_id"]

        # 両方の列で同じセッションIDが使われている
        assert anon_df["患者ID"].iloc[0].endswith(f"_{session_id}")
        assert anon_df["氏名"].iloc[0].endswith(f"_{session_id}")


class TestCollisionCheck:
    """衝突チェックのテスト"""

    def test_no_collision(self):
        """衝突がない場合"""
        df = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
        })
        warnings = check_collision(df)
        assert len(warnings) == 0

    def test_collision_detected(self):
        """衝突が検出される場合"""
        df = pd.DataFrame({
            "患者ID": ["PATIENT_001", "P002"],  # 匿名化パターンと似た値
        })
        warnings = check_collision(df)
        assert len(warnings) == 1
        assert "PATIENT_001" in warnings[0]

    def test_multiple_collisions(self):
        """複数の衝突"""
        df = pd.DataFrame({
            "col1": ["PERSON_001", "normal"],
            "col2": ["PHONE_002", "normal"],
        })
        warnings = check_collision(df)
        assert len(warnings) == 2

    def test_collision_pattern_variations(self):
        """様々な匿名化パターンの検出"""
        patterns_to_test = [
            "PATIENT_001",
            "PERSON_999",
            "PHONE_123",
            "EMAIL_001",
            "ADDR_456",
            "ID_001",
        ]
        for pattern in patterns_to_test:
            df = pd.DataFrame({"col": [pattern]})
            warnings = check_collision(df)
            assert len(warnings) == 1, f"Pattern {pattern} should be detected"


class TestValueBasedRestore:
    """値ベース復元のテスト"""

    def test_restore_regardless_of_column_name(self):
        """列名に関係なく復元できる"""
        # 元データ
        original_df = pd.DataFrame({
            "患者ID": ["P001", "P002"],
            "氏名": ["山田太郎", "鈴木花子"],
        })
        pii_columns = detect_pii_columns(original_df)
        anon_df, mapping = anonymize_dataframe(original_df, pii_columns, strategy="replace")

        # LLMが列名を変更したと仮定
        renamed_df = anon_df.rename(columns={"患者ID": "ID", "氏名": "名前"})

        # 復元は列名に関係なく動作する
        restored_df = deanonymize_dataframe(renamed_df, mapping)

        assert restored_df["ID"].iloc[0] == "P001"
        assert restored_df["名前"].iloc[0] == "山田太郎"

    def test_restore_with_new_column(self):
        """新しい列に配置されても復元できる"""
        original_df = pd.DataFrame({"患者ID": ["P001"]})
        pii_columns = detect_pii_columns(original_df)
        anon_df, mapping = anonymize_dataframe(original_df, pii_columns, strategy="replace")

        session_id = mapping["metadata"]["session_id"]
        anon_value = f"PATIENT_001_{session_id}"

        # LLMが新しい列を作成したと仮定
        new_df = pd.DataFrame({
            "分析結果": [f"{anon_value}の来院回数は3回"],
            "備考": ["通常"],
        })

        # 復元
        restored_df = deanonymize_dataframe(new_df, mapping)

        assert restored_df["分析結果"].iloc[0] == "P001の来院回数は3回"

    def test_restore_shuffled_rows(self):
        """行がシャッフルされても復元できる"""
        original_df = pd.DataFrame({
            "患者ID": ["P001", "P002", "P003"],
            "氏名": ["山田太郎", "鈴木花子", "佐藤一郎"],
        })
        pii_columns = detect_pii_columns(original_df)
        anon_df, mapping = anonymize_dataframe(original_df, pii_columns, strategy="replace")

        # 行をシャッフル
        shuffled_df = anon_df.iloc[[2, 0, 1]].reset_index(drop=True)

        # 復元
        restored_df = deanonymize_dataframe(shuffled_df, mapping)

        # シャッフルされた順序で正しく復元される
        assert restored_df["患者ID"].iloc[0] == "P003"
        assert restored_df["患者ID"].iloc[1] == "P001"
        assert restored_df["患者ID"].iloc[2] == "P002"
