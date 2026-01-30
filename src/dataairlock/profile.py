"""DataAirlock プロファイル管理モジュール

PII処理設定のプロファイル保存・読み込み機能を提供します。
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Literal

# プロファイル保存ディレクトリ
DEFAULT_PROFILE_DIR = Path.home() / ".config" / "dataairlock" / "profiles"

# 処理アクション
ActionType = Literal["replace", "generalize", "delete", "skip"]


class Profile:
    """PII処理プロファイル"""

    def __init__(
        self,
        name: str,
        column_rules: dict[str, ActionType] | None = None,
        pii_type_defaults: dict[str, ActionType] | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
        last_used_at: datetime | None = None,
    ):
        self.name = name
        self.column_rules = column_rules or {}
        self.pii_type_defaults = pii_type_defaults or {}
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.last_used_at = last_used_at

    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "column_rules": self.column_rules,
            "pii_type_defaults": self.pii_type_defaults,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Profile:
        """辞書形式から復元"""
        return cls(
            name=data["name"],
            column_rules=data.get("column_rules", {}),
            pii_type_defaults=data.get("pii_type_defaults", {}),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_used_at=datetime.fromisoformat(data["last_used_at"]) if data.get("last_used_at") else None,
        )

    def get_action_for_column(
        self,
        column_name: str,
        pii_type: str | None = None,
    ) -> ActionType | None:
        """
        列に対する処理アクションを取得

        優先順位:
        1. column_rules の列名完全一致
        2. pii_type_defaults のPIIタイプによるデフォルト
        3. マッチしない場合は None
        """
        # 1. 列名完全一致
        if column_name in self.column_rules:
            return self.column_rules[column_name]

        # 2. PIIタイプによるデフォルト
        if pii_type and pii_type in self.pii_type_defaults:
            return self.pii_type_defaults[pii_type]

        return None

    def update_column_rule(self, column_name: str, action: ActionType) -> None:
        """列ルールを更新"""
        self.column_rules[column_name] = action
        self.updated_at = datetime.now()

    def update_pii_type_default(self, pii_type: str, action: ActionType) -> None:
        """PIIタイプのデフォルトを更新"""
        self.pii_type_defaults[pii_type] = action
        self.updated_at = datetime.now()

    def mark_used(self) -> None:
        """使用日時を記録"""
        self.last_used_at = datetime.now()


class ProfileManager:
    """プロファイル管理クラス"""

    def __init__(self, profile_dir: Path | None = None):
        self.profile_dir = profile_dir or DEFAULT_PROFILE_DIR
        self._ensure_profile_dir()

    def _ensure_profile_dir(self) -> None:
        """プロファイルディレクトリを作成"""
        self.profile_dir.mkdir(parents=True, exist_ok=True)

    def _get_profile_path(self, name: str) -> Path:
        """プロファイルファイルのパスを取得"""
        # ファイル名に使えない文字を置換
        safe_name = name.replace("/", "_").replace("\\", "_")
        return self.profile_dir / f"{safe_name}.json"

    def save(self, profile: Profile) -> Path:
        """プロファイルを保存"""
        profile.updated_at = datetime.now()
        path = self._get_profile_path(profile.name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profile.to_dict(), f, ensure_ascii=False, indent=2)
        return path

    def load(self, name: str) -> Profile | None:
        """プロファイルを読み込み"""
        path = self._get_profile_path(name)
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return Profile.from_dict(data)

    def delete(self, name: str) -> bool:
        """プロファイルを削除"""
        path = self._get_profile_path(name)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_profiles(self) -> list[Profile]:
        """全プロファイルを一覧取得"""
        profiles = []
        for path in self.profile_dir.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                profiles.append(Profile.from_dict(data))
            except (json.JSONDecodeError, KeyError):
                continue
        # 最終使用日時でソート（新しい順）
        profiles.sort(
            key=lambda p: p.last_used_at or p.updated_at or p.created_at,
            reverse=True,
        )
        return profiles

    def exists(self, name: str) -> bool:
        """プロファイルが存在するか確認"""
        return self._get_profile_path(name).exists()

    def export_profile(self, name: str, output_path: Path) -> bool:
        """プロファイルをエクスポート"""
        profile = self.load(name)
        if not profile:
            return False
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(profile.to_dict(), f, ensure_ascii=False, indent=2)
        return True

    def import_profile(self, input_path: Path, overwrite: bool = False) -> Profile | None:
        """プロファイルをインポート"""
        if not input_path.exists():
            return None
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        profile = Profile.from_dict(data)
        if self.exists(profile.name) and not overwrite:
            return None
        self.save(profile)
        return profile

    def create_default_profile(self) -> Profile:
        """デフォルトプロファイルを作成"""
        default = Profile(
            name="default",
            column_rules={},
            pii_type_defaults={
                "patient_id": "replace",
                "name": "replace",
                "name_kana": "replace",
                "birthdate": "generalize",
                "age": "generalize",
                "address": "generalize",
                "phone": "replace",
                "email": "replace",
                "my_number": "replace",
                "unknown": "replace",
            },
        )
        self.save(default)
        return default


def create_profile_from_actions(
    name: str,
    column_actions: dict[str, tuple[str, ActionType]],
) -> Profile:
    """
    処理結果からプロファイルを作成

    Args:
        name: プロファイル名
        column_actions: {列名: (PIIタイプ, アクション)} の辞書
    """
    column_rules = {}
    pii_type_defaults = {}

    for col_name, (pii_type, action) in column_actions.items():
        column_rules[col_name] = action
        # PIIタイプのデフォルトも設定（同じタイプで最後に設定された値が優先）
        if pii_type:
            pii_type_defaults[pii_type] = action

    return Profile(
        name=name,
        column_rules=column_rules,
        pii_type_defaults=pii_type_defaults,
    )


# PIIタイプ名のマッピング（anonymizer.py の PIIType と対応）
PII_TYPE_MAPPING = {
    "patient_id": "PATIENT_ID",
    "name": "NAME",
    "name_kana": "NAME_KANA",
    "birthdate": "BIRTHDATE",
    "age": "AGE",
    "address": "ADDRESS",
    "phone": "PHONE",
    "email": "EMAIL",
    "my_number": "MY_NUMBER",
    "postal_code": "POSTAL_CODE",
    "unknown": "UNKNOWN",
}

# 逆マッピング
PII_TYPE_REVERSE_MAPPING = {v: k for k, v in PII_TYPE_MAPPING.items()}


def pii_type_to_profile_key(pii_type: str) -> str:
    """PIIType の値をプロファイルキーに変換"""
    return PII_TYPE_REVERSE_MAPPING.get(pii_type, pii_type.lower())


def profile_key_to_pii_type(key: str) -> str:
    """プロファイルキーを PIIType の値に変換"""
    return PII_TYPE_MAPPING.get(key, key.upper())
