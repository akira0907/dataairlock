"""データ匿名化ロジック"""

import base64
import hashlib
import json
import random
import re
import string
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import pandas as pd
from cryptography.fernet import Fernet, InvalidToken


def generate_session_id(length: int = 4) -> str:
    """セッションIDを生成（例: K9M2, A7XB）

    4文字で36^4 = 1,679,616通り（衝突リスク低減）
    """
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))


# 匿名化パターン検出用（衝突チェック用）
ANON_PATTERN = re.compile(
    r'^(PATIENT|PERSON|PERSON_KANA|PHONE|EMAIL|ADDR|BIRTHDATE|AGE|MYNUMBER|ID)_\d{3}'
)


def check_collision(df: pd.DataFrame) -> list[str]:
    """元データに匿名化パターンと似た値が存在するかチェック"""
    warnings = []
    for col in df.columns:
        for val in df[col].dropna().unique():
            str_val = str(val)
            if ANON_PATTERN.match(str_val):
                warnings.append(
                    f"警告: 列'{col}'に匿名化パターンと似た値があります: {str_val}"
                )
    return warnings


class PIIType(Enum):
    """個人情報の種類"""
    NAME = "氏名"
    NAME_KANA = "氏名カナ"
    PATIENT_ID = "患者ID"
    BIRTHDATE = "生年月日"
    AGE = "年齢"
    PHONE = "電話番号"
    EMAIL = "メールアドレス"
    ADDRESS = "住所"
    MY_NUMBER = "マイナンバー"
    UNKNOWN = "不明"


# PIIType別のセマンティックプレフィックス
SEMANTIC_PREFIXES: dict[PIIType, str] = {
    PIIType.PATIENT_ID: "PATIENT",
    PIIType.NAME: "PERSON",
    PIIType.NAME_KANA: "PERSON_KANA",
    PIIType.PHONE: "PHONE",
    PIIType.EMAIL: "EMAIL",
    PIIType.ADDRESS: "ADDR",
    PIIType.BIRTHDATE: "BIRTHDATE",
    PIIType.AGE: "AGE",
    PIIType.MY_NUMBER: "MYNUMBER",
    PIIType.UNKNOWN: "ID",
}


class Confidence(Enum):
    """検出確度"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PIIColumnResult:
    """列単位のPII検出結果"""
    column_name: str
    pii_type: PIIType
    confidence: Confidence
    matched_by: str  # "column_name" or "content"
    sample_values: list[str] = field(default_factory=list)


@dataclass
class PIIValueResult:
    """セル単位のPII検出結果"""
    value: str
    pii_type: PIIType
    start: int
    end: int
    matched_pattern: str


# 列名パターン定義（日本の医療現場向け）
COLUMN_NAME_PATTERNS: dict[PIIType, list[tuple[str, Confidence]]] = {
    PIIType.NAME: [
        (r"^(患者)?氏名$", Confidence.HIGH),
        (r"^(患者)?名前$", Confidence.HIGH),
        (r"^name$", Confidence.MEDIUM),
        (r"^full_?name$", Confidence.HIGH),
        (r"姓名", Confidence.HIGH),
        (r"漢字氏名", Confidence.HIGH),
        (r"患者名", Confidence.HIGH),
    ],
    PIIType.NAME_KANA: [
        (r"^(氏名)?カナ$", Confidence.HIGH),
        (r"^(氏名)?かな$", Confidence.HIGH),
        (r"^フリガナ$", Confidence.HIGH),
        (r"^ふりがな$", Confidence.HIGH),
        (r"カナ氏名", Confidence.HIGH),
        (r"カナ名", Confidence.HIGH),
        (r"^kana$", Confidence.MEDIUM),
        (r"name_kana", Confidence.HIGH),
    ],
    PIIType.PATIENT_ID: [
        (r"^患者ID$", Confidence.HIGH),
        (r"^患者番号$", Confidence.HIGH),
        (r"^カルテ番号$", Confidence.HIGH),
        (r"^カルテNo\.?$", Confidence.HIGH),
        (r"^診察券番号$", Confidence.HIGH),
        (r"^patient_?id$", Confidence.HIGH),
        (r"^chart_?no$", Confidence.HIGH),
        (r"^ID$", Confidence.LOW),
        (r"受付番号", Confidence.MEDIUM),
    ],
    PIIType.BIRTHDATE: [
        (r"^生年月日$", Confidence.HIGH),
        (r"^誕生日$", Confidence.HIGH),
        (r"^birth_?date$", Confidence.HIGH),
        (r"^birthday$", Confidence.HIGH),
        (r"^dob$", Confidence.HIGH),
        (r"^生年$", Confidence.MEDIUM),
    ],
    PIIType.AGE: [
        (r"^年齢$", Confidence.HIGH),
        (r"^age$", Confidence.HIGH),
        (r"^満年齢$", Confidence.HIGH),
    ],
    PIIType.PHONE: [
        (r"^電話番号$", Confidence.HIGH),
        (r"^TEL$", Confidence.HIGH),
        (r"^tel$", Confidence.HIGH),
        (r"^phone$", Confidence.HIGH),
        (r"^携帯$", Confidence.HIGH),
        (r"^携帯番号$", Confidence.HIGH),
        (r"^連絡先$", Confidence.MEDIUM),
        (r"緊急連絡先", Confidence.HIGH),
        (r"自宅電話", Confidence.HIGH),
        (r"勤務先電話", Confidence.HIGH),
    ],
    PIIType.EMAIL: [
        (r"^(e-?)?mail$", Confidence.HIGH),
        (r"^メール$", Confidence.HIGH),
        (r"^メールアドレス$", Confidence.HIGH),
        (r"^email_?address$", Confidence.HIGH),
    ],
    PIIType.ADDRESS: [
        (r"^住所$", Confidence.HIGH),
        (r"^address$", Confidence.HIGH),
        (r"^自宅住所$", Confidence.HIGH),
        (r"^現住所$", Confidence.HIGH),
        (r"^勤務先住所$", Confidence.HIGH),
        (r"^郵便番号$", Confidence.HIGH),
        (r"^postal_?code$", Confidence.HIGH),
        (r"^zip_?code$", Confidence.HIGH),
        (r"都道府県", Confidence.MEDIUM),
        (r"市区町村", Confidence.MEDIUM),
    ],
    PIIType.MY_NUMBER: [
        (r"^マイナンバー$", Confidence.HIGH),
        (r"^個人番号$", Confidence.HIGH),
        (r"^my_?number$", Confidence.HIGH),
    ],
}

# セル値検出用の正規表現パターン
VALUE_PATTERNS: dict[PIIType, list[tuple[str, str]]] = {
    PIIType.PHONE: [
        # 固定電話（市外局番あり）
        (r"0\d{1,4}-\d{1,4}-\d{4}", "電話番号（ハイフンあり）"),
        (r"0\d{9,10}", "電話番号（ハイフンなし）"),
        # 携帯電話
        (r"0[789]0-\d{4}-\d{4}", "携帯番号（ハイフンあり）"),
        (r"0[789]0\d{8}", "携帯番号（ハイフンなし）"),
    ],
    PIIType.EMAIL: [
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "メールアドレス"),
    ],
    PIIType.MY_NUMBER: [
        # マイナンバー（12桁）
        (r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b", "マイナンバー形式"),
        (r"\b\d{12}\b", "12桁数字"),
    ],
    PIIType.BIRTHDATE: [
        # 西暦（スラッシュ・ハイフン区切り）
        (r"(19|20)\d{2}[/\-](0?[1-9]|1[0-2])[/\-](0?[1-9]|[12]\d|3[01])", "生年月日（西暦）"),
        # 西暦（日本語区切り）
        (r"(19|20)\d{2}年(0?[1-9]|1[0-2])月(0?[1-9]|[12]\d|3[01])日", "生年月日（西暦・日本語）"),
        # 和暦
        (r"(明治|大正|昭和|平成|令和)\d{1,2}年(0?[1-9]|1[0-2])月(0?[1-9]|[12]\d|3[01])日", "生年月日（和暦）"),
        # コンパクト形式
        (r"(?<!\d)(19|20)\d{6}(?!\d)", "生年月日（8桁数字）"),
    ],
    PIIType.ADDRESS: [
        # 郵便番号
        (r"\b\d{3}-\d{4}\b", "郵便番号"),
        # 都道府県から始まる住所
        (r"(東京都|北海道|(?:京都|大阪)府|.{2,3}県).{2,}", "住所（都道府県）"),
    ],
    PIIType.AGE: [
        (r"(?<!\d)\d{1,3}歳", "年齢"),
    ],
}


class PIIDetector:
    """個人情報検出クラス"""

    def __init__(self):
        self._compiled_column_patterns: dict[PIIType, list[tuple[re.Pattern, Confidence]]] = {}
        self._compiled_value_patterns: dict[PIIType, list[tuple[re.Pattern, str]]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """正規表現パターンをコンパイル"""
        for pii_type, patterns in COLUMN_NAME_PATTERNS.items():
            self._compiled_column_patterns[pii_type] = [
                (re.compile(pattern, re.IGNORECASE), conf)
                for pattern, conf in patterns
            ]

        for pii_type, patterns in VALUE_PATTERNS.items():
            self._compiled_value_patterns[pii_type] = [
                (re.compile(pattern), desc)
                for pattern, desc in patterns
            ]

    def detect_pii_columns(self, df: pd.DataFrame) -> dict[str, PIIColumnResult]:
        """
        DataFrameの列からPIIを検出する

        Args:
            df: 検査対象のDataFrame

        Returns:
            列名をキー、PIIColumnResultを値とする辞書
        """
        results: dict[str, PIIColumnResult] = {}

        for col in df.columns:
            # 1. 列名パターンマッチング
            col_result = self._detect_by_column_name(col)
            if col_result:
                # サンプル値を追加
                col_result.sample_values = self._get_sample_values(df[col])
                results[col] = col_result
                continue

            # 2. データ内容からの推定
            content_result = self._detect_by_content(col, df[col])
            if content_result:
                results[col] = content_result

        return results

    def _detect_by_column_name(self, column_name: str) -> PIIColumnResult | None:
        """列名パターンによるPII検出"""
        for pii_type, patterns in self._compiled_column_patterns.items():
            for pattern, confidence in patterns:
                if pattern.search(column_name):
                    return PIIColumnResult(
                        column_name=column_name,
                        pii_type=pii_type,
                        confidence=confidence,
                        matched_by="column_name",
                    )
        return None

    def _detect_by_content(self, column_name: str, series: pd.Series) -> PIIColumnResult | None:
        """データ内容からPIIを推定"""
        sample_values = self._get_sample_values(series)
        if not sample_values:
            return None

        # 各PIIタイプについてマッチ率を計算
        best_match: tuple[PIIType, float, Confidence] | None = None

        for pii_type, patterns in self._compiled_value_patterns.items():
            match_count = 0
            for value in sample_values:
                for pattern, _ in patterns:
                    if pattern.search(str(value)):
                        match_count += 1
                        break

            if match_count > 0:
                match_ratio = match_count / len(sample_values)
                # 確度を決定
                if match_ratio >= 0.8:
                    confidence = Confidence.HIGH
                elif match_ratio >= 0.5:
                    confidence = Confidence.MEDIUM
                else:
                    confidence = Confidence.LOW

                if best_match is None or match_ratio > best_match[1]:
                    best_match = (pii_type, match_ratio, confidence)

        if best_match and best_match[1] >= 0.3:  # 最低30%以上のマッチ率
            return PIIColumnResult(
                column_name=column_name,
                pii_type=best_match[0],
                confidence=best_match[2],
                matched_by="content",
                sample_values=sample_values,
            )

        return None

    def _get_sample_values(self, series: pd.Series, max_samples: int = 10) -> list[str]:
        """列からサンプル値を取得"""
        non_null = series.dropna().astype(str)
        unique_values = non_null.unique()
        return list(unique_values[:max_samples])

    def detect_pii_values(self, series: pd.Series) -> list[list[PIIValueResult]]:
        """
        Series内の各セルからPIIを検出する

        Args:
            series: 検査対象のSeries

        Returns:
            各セルのPII検出結果のリスト（セルごとにリスト）
        """
        results: list[list[PIIValueResult]] = []

        for value in series:
            cell_results = self._detect_pii_in_text(str(value) if pd.notna(value) else "")
            results.append(cell_results)

        return results

    def _detect_pii_in_text(self, text: str) -> list[PIIValueResult]:
        """テキスト内のPIIを検出"""
        results: list[PIIValueResult] = []

        for pii_type, patterns in self._compiled_value_patterns.items():
            for pattern, desc in patterns:
                for match in pattern.finditer(text):
                    results.append(PIIValueResult(
                        value=match.group(),
                        pii_type=pii_type,
                        start=match.start(),
                        end=match.end(),
                        matched_pattern=desc,
                    ))

        # 位置でソート
        results.sort(key=lambda x: x.start)
        return results


# 便利関数
def detect_pii_columns(df: pd.DataFrame) -> dict[str, PIIColumnResult]:
    """DataFrameの列からPIIを検出する（便利関数）"""
    detector = PIIDetector()
    return detector.detect_pii_columns(df)


def detect_pii_values(series: pd.Series) -> list[list[PIIValueResult]]:
    """Series内の各セルからPIIを検出する（便利関数）"""
    detector = PIIDetector()
    return detector.detect_pii_values(series)


class AnonymizationStrategy(Enum):
    """匿名化戦略"""
    REPLACE = "replace"      # ランダムUUIDに置換
    GENERALIZE = "generalize"  # 一般化（生年月日→年代、住所→都道府県）
    DELETE = "delete"        # 列ごと削除


# 都道府県抽出用パターン
PREFECTURE_PATTERN = re.compile(
    r"^(東京都|北海道|(?:京都|大阪)府|"
    r"青森県|岩手県|宮城県|秋田県|山形県|福島県|"
    r"茨城県|栃木県|群馬県|埼玉県|千葉県|神奈川県|"
    r"新潟県|富山県|石川県|福井県|山梨県|長野県|"
    r"岐阜県|静岡県|愛知県|三重県|"
    r"滋賀県|兵庫県|奈良県|和歌山県|"
    r"鳥取県|島根県|岡山県|広島県|山口県|"
    r"徳島県|香川県|愛媛県|高知県|"
    r"福岡県|佐賀県|長崎県|熊本県|大分県|宮崎県|鹿児島県|沖縄県)"
)

# 生年月日から年代抽出用パターン
YEAR_PATTERN_WESTERN = re.compile(r"(19|20)(\d{2})")
WAREKI_TO_SEIREKI = {
    "明治": 1868,
    "大正": 1912,
    "昭和": 1926,
    "平成": 1989,
    "令和": 2019,
}
YEAR_PATTERN_JAPANESE = re.compile(r"(明治|大正|昭和|平成|令和)(\d{1,2})年")


def _derive_key_from_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """パスワードからFernet用の鍵を導出"""
    if salt is None:
        salt = hashlib.sha256(password.encode()).digest()[:16]
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)
    fernet_key = base64.urlsafe_b64encode(key)
    return fernet_key, salt


def _generalize_birthdate(value: str) -> str:
    """生年月日を年代に一般化"""
    if pd.isna(value):
        return value

    value_str = str(value)

    # 西暦パターン
    match = YEAR_PATTERN_WESTERN.search(value_str)
    if match:
        year = int(match.group(1) + match.group(2))
        decade = (year // 10) * 10
        return f"{decade}年代"

    # 和暦パターン
    match = YEAR_PATTERN_JAPANESE.search(value_str)
    if match:
        era = match.group(1)
        era_year = int(match.group(2))
        base_year = WAREKI_TO_SEIREKI.get(era, 2000)
        year = base_year + era_year - 1
        decade = (year // 10) * 10
        return f"{decade}年代"

    return value_str


def _generalize_address(value: str) -> str:
    """住所を都道府県のみに一般化"""
    if pd.isna(value):
        return value

    value_str = str(value)
    match = PREFECTURE_PATTERN.match(value_str)
    if match:
        return match.group(1)

    return value_str


def _generalize_age(value: str) -> str:
    """年齢を年代に一般化"""
    if pd.isna(value):
        return value

    value_str = str(value)
    # 数字を抽出
    match = re.search(r"(\d{1,3})", value_str)
    if match:
        age = int(match.group(1))
        decade = (age // 10) * 10
        return f"{decade}代"

    return value_str


def anonymize_dataframe(
    df: pd.DataFrame,
    pii_columns: dict[str, PIIColumnResult],
    strategy: Literal["replace", "generalize", "delete"] = "replace",
    original_file: str | None = None,
    session_id: str | None = None,
    global_mapping: dict[str, dict[str, str]] | None = None,
) -> tuple[pd.DataFrame, dict]:
    """
    DataFrameを匿名化する

    Args:
        df: 匿名化対象のDataFrame
        pii_columns: detect_pii_columns()の結果
        strategy: 匿名化戦略 ('replace', 'generalize', 'delete')
        original_file: 元ファイル名（メタデータ用）
        session_id: セッションID（指定しない場合は自動生成）
        global_mapping: 複数ファイル間で共有するマッピング（同じ値に同じIDを割り当てる）

    Returns:
        (匿名化されたDataFrame, マッピング辞書)
    """
    anonymized_df = df.copy()

    # セッションIDを生成または使用
    if session_id is None:
        session_id = generate_session_id()

    # グローバルマッピングを初期化
    if global_mapping is None:
        global_mapping = {}

    mapping: dict[str, Any] = {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "strategy": strategy,
            "original_file": original_file,
            "columns_processed": list(pii_columns.keys()),
            "session_id": session_id,
        }
    }

    for col_name, pii_result in pii_columns.items():
        if col_name not in anonymized_df.columns:
            continue

        if strategy == "delete":
            anonymized_df = anonymized_df.drop(columns=[col_name])
            mapping[col_name] = {"action": "deleted", "pii_type": pii_result.pii_type.value}

        elif strategy == "generalize":
            col_mapping = _generalize_column(
                anonymized_df[col_name], pii_result.pii_type, session_id,
                global_mapping.get(col_name),
            )
            # グローバルマッピングを更新
            if col_name not in global_mapping:
                global_mapping[col_name] = {}
            global_mapping[col_name].update(col_mapping)

            anonymized_df[col_name] = anonymized_df[col_name].map(
                lambda x: col_mapping.get(str(x) if pd.notna(x) else x, x)
            )
            mapping[col_name] = {
                "action": "generalized",
                "pii_type": pii_result.pii_type.value,
                "values": col_mapping,
            }

        else:  # replace
            col_mapping = _replace_column(
                anonymized_df[col_name], pii_result.pii_type, session_id,
                global_mapping.get(col_name),
            )
            # グローバルマッピングを更新
            if col_name not in global_mapping:
                global_mapping[col_name] = {}
            global_mapping[col_name].update(col_mapping)

            anonymized_df[col_name] = anonymized_df[col_name].map(
                lambda x: col_mapping.get(str(x) if pd.notna(x) else x, x)
            )
            mapping[col_name] = {
                "action": "replaced",
                "pii_type": pii_result.pii_type.value,
                "values": col_mapping,
            }

    return anonymized_df, mapping


def _replace_column(
    series: pd.Series,
    pii_type: PIIType = PIIType.UNKNOWN,
    session_id: str | None = None,
    existing_mapping: dict[str, str] | None = None,
) -> dict[str, str]:
    """列の値をセマンティックIDで置換するマッピングを生成

    Args:
        series: 対象列
        pii_type: PIIタイプ
        session_id: セッションID
        existing_mapping: 既存のマッピング（同じ値に同じIDを割り当てる）

    Returns:
        値→匿名化IDのマッピング
    """
    mapping: dict[str, str] = {}
    prefix = SEMANTIC_PREFIXES.get(pii_type, "ID")

    # 既存のマッピングから最大カウンタを取得
    if existing_mapping:
        mapping.update(existing_mapping)
        # 既存IDから最大番号を抽出
        max_counter = 0
        for anon_id in existing_mapping.values():
            # PERSON_001_XXXX 形式からカウンタを抽出
            parts = anon_id.split("_")
            if len(parts) >= 2:
                try:
                    num = int(parts[1])
                    max_counter = max(max_counter, num)
                except ValueError:
                    pass
        counter = max_counter + 1
    else:
        counter = 1

    for value in series.dropna().unique():
        str_value = str(value)
        if str_value not in mapping:
            # ゼロパディング（3桁、999超えたら自動拡張）
            if session_id:
                mapping[str_value] = f"{prefix}_{counter:03d}_{session_id}"
            else:
                mapping[str_value] = f"{prefix}_{counter:03d}"
            counter += 1
    return mapping


def _generalize_column(
    series: pd.Series,
    pii_type: PIIType,
    session_id: str | None = None,
    existing_mapping: dict[str, str] | None = None,
) -> dict[str, str]:
    """列の値を一般化するマッピングを生成

    Args:
        series: 対象列
        pii_type: PIIタイプ
        session_id: セッションID
        existing_mapping: 既存のマッピング（同じ値に同じIDを割り当てる）

    Returns:
        値→一般化された値のマッピング
    """
    mapping: dict[str, str] = {}
    prefix = SEMANTIC_PREFIXES.get(pii_type, "ID")

    # 既存のマッピングから最大カウンタを取得
    if existing_mapping:
        mapping.update(existing_mapping)
        max_counter = 0
        for anon_id in existing_mapping.values():
            parts = anon_id.split("_")
            if len(parts) >= 2:
                try:
                    num = int(parts[1])
                    max_counter = max(max_counter, num)
                except ValueError:
                    pass
        counter = max_counter + 1
    else:
        counter = 1

    for value in series.dropna().unique():
        str_value = str(value)
        if str_value in mapping:
            continue

        if pii_type == PIIType.BIRTHDATE:
            mapping[str_value] = _generalize_birthdate(str_value)
        elif pii_type == PIIType.ADDRESS:
            mapping[str_value] = _generalize_address(str_value)
        elif pii_type == PIIType.AGE:
            mapping[str_value] = _generalize_age(str_value)
        else:
            # 一般化ルールがない場合はセマンティックID置換にフォールバック
            if session_id:
                mapping[str_value] = f"{prefix}_{counter:03d}_{session_id}"
            else:
                mapping[str_value] = f"{prefix}_{counter:03d}"
            counter += 1

    return mapping


def save_mapping(
    mapping: dict,
    filepath: str | Path,
    password: str,
) -> None:
    """
    マッピングを暗号化して保存

    Args:
        mapping: 匿名化マッピング辞書
        filepath: 保存先パス
        password: 暗号化パスワード
    """
    filepath = Path(filepath)

    # JSON形式にシリアライズ
    json_data = json.dumps(mapping, ensure_ascii=False, indent=2)

    # 暗号化
    fernet_key, salt = _derive_key_from_password(password)
    fernet = Fernet(fernet_key)
    encrypted_data = fernet.encrypt(json_data.encode("utf-8"))

    # salt + encrypted_data を保存
    with open(filepath, "wb") as f:
        f.write(salt + encrypted_data)


def load_mapping(
    filepath: str | Path,
    password: str,
) -> dict:
    """
    暗号化されたマッピングを読み込み

    Args:
        filepath: マッピングファイルパス
        password: 復号パスワード

    Returns:
        マッピング辞書

    Raises:
        ValueError: パスワードが間違っている場合
    """
    filepath = Path(filepath)

    with open(filepath, "rb") as f:
        data = f.read()

    # salt と encrypted_data を分離
    salt = data[:16]
    encrypted_data = data[16:]

    # 復号
    fernet_key, _ = _derive_key_from_password(password, salt)
    fernet = Fernet(fernet_key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken as e:
        raise ValueError("パスワードが正しくないか、ファイルが破損しています") from e

    return json.loads(decrypted_data.decode("utf-8"))


def deanonymize_dataframe(
    df: pd.DataFrame,
    mapping: dict,
) -> pd.DataFrame:
    """
    匿名化を解除してDataFrameを復元

    値ベースの復元: 列名に関係なく全セルをスキャンして復元する。
    これにより、LLMがデータを並べ替えたり、新しい列に配置した場合でも
    正しく復元できる。

    Args:
        df: 匿名化されたDataFrame
        mapping: 匿名化時に生成されたマッピング

    Returns:
        復元されたDataFrame
    """
    restored_df = df.copy()

    # 全列の逆マッピングを統合して作成
    reverse_map: dict[str, str] = {}
    for col_name, col_info in mapping.items():
        if col_name == "metadata":
            continue

        if col_info.get("action") == "deleted":
            # 削除された列は復元不可
            continue

        values_mapping = col_info.get("values", {})
        if not values_mapping:
            continue

        # 逆マッピングを統合
        for orig, anon in values_mapping.items():
            reverse_map[anon] = orig

    def restore_value(x):
        """セル値を復元（完全一致または部分文字列置換）"""
        if pd.isna(x):
            return x
        str_x = str(x)

        # まず完全一致を試す
        if str_x in reverse_map:
            return reverse_map[str_x]

        # 完全一致しない場合、部分文字列として置換を試す
        result = str_x
        for anon, orig in reverse_map.items():
            if anon in result:
                result = result.replace(anon, orig)

        return result

    # 全列・全セルをスキャンして復元
    for col in restored_df.columns:
        restored_df[col] = restored_df[col].apply(restore_value)

    return restored_df


class Anonymizer:
    """個人情報を匿名化するクラス"""

    def __init__(self):
        self.mappings: dict[str, Any] = {}
        self.detector = PIIDetector()

    def anonymize(
        self,
        df: pd.DataFrame,
        strategy: Literal["replace", "generalize", "delete"] = "replace",
        columns: list[str] | None = None,
    ) -> tuple[pd.DataFrame, dict]:
        """
        DataFrameを匿名化する

        Args:
            df: 匿名化対象のDataFrame
            strategy: 匿名化戦略
            columns: 匿名化対象列（Noneの場合は自動検出）

        Returns:
            (匿名化されたDataFrame, マッピング辞書)
        """
        # PII列を検出または指定された列を使用
        if columns is None:
            pii_columns = self.detector.detect_pii_columns(df)
        else:
            pii_columns = {
                col: PIIColumnResult(
                    column_name=col,
                    pii_type=PIIType.UNKNOWN,
                    confidence=Confidence.HIGH,
                    matched_by="manual",
                )
                for col in columns
                if col in df.columns
            }

        anonymized_df, mapping = anonymize_dataframe(df, pii_columns, strategy)
        self.mappings = mapping
        return anonymized_df, mapping

    def deanonymize(self, df: pd.DataFrame, mapping: dict | None = None) -> pd.DataFrame:
        """匿名化を解除する"""
        if mapping is None:
            mapping = self.mappings
        return deanonymize_dataframe(df, mapping)
