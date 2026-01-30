"""プロファイル管理機能のテスト"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from dataairlock.profile import (
    Profile,
    ProfileManager,
    create_profile_from_actions,
    pii_type_to_profile_key,
    profile_key_to_pii_type,
)


class TestProfile:
    """Profile クラスのテスト"""

    def test_create_profile(self):
        """プロファイル作成"""
        profile = Profile(
            name="test",
            column_rules={"氏名": "replace"},
            pii_type_defaults={"name": "replace"},
        )
        assert profile.name == "test"
        assert profile.column_rules == {"氏名": "replace"}
        assert profile.pii_type_defaults == {"name": "replace"}
        assert profile.created_at is not None
        assert profile.updated_at is not None

    def test_to_dict(self):
        """辞書形式への変換"""
        profile = Profile(
            name="test",
            column_rules={"氏名": "replace"},
            pii_type_defaults={"name": "replace"},
        )
        data = profile.to_dict()
        assert data["name"] == "test"
        assert data["column_rules"] == {"氏名": "replace"}
        assert data["pii_type_defaults"] == {"name": "replace"}
        assert "created_at" in data
        assert "updated_at" in data

    def test_from_dict(self):
        """辞書形式からの復元"""
        data = {
            "name": "test",
            "column_rules": {"氏名": "replace"},
            "pii_type_defaults": {"name": "replace"},
            "created_at": "2026-01-01T00:00:00",
            "updated_at": "2026-01-01T00:00:00",
            "last_used_at": None,
        }
        profile = Profile.from_dict(data)
        assert profile.name == "test"
        assert profile.column_rules == {"氏名": "replace"}
        assert profile.pii_type_defaults == {"name": "replace"}

    def test_get_action_for_column_by_name(self):
        """列名でアクションを取得"""
        profile = Profile(
            name="test",
            column_rules={"氏名": "replace", "住所": "generalize"},
        )
        assert profile.get_action_for_column("氏名") == "replace"
        assert profile.get_action_for_column("住所") == "generalize"
        assert profile.get_action_for_column("不明") is None

    def test_get_action_for_column_by_pii_type(self):
        """PIIタイプでアクションを取得"""
        profile = Profile(
            name="test",
            column_rules={},
            pii_type_defaults={"name": "replace", "address": "generalize"},
        )
        assert profile.get_action_for_column("名前", pii_type="name") == "replace"
        assert profile.get_action_for_column("住所", pii_type="address") == "generalize"

    def test_column_name_takes_priority(self):
        """列名がPIIタイプより優先"""
        profile = Profile(
            name="test",
            column_rules={"氏名": "delete"},
            pii_type_defaults={"name": "replace"},
        )
        # 列名がマッチする場合は列ルールが優先
        assert profile.get_action_for_column("氏名", pii_type="name") == "delete"
        # 列名がマッチしない場合はPIIタイプデフォルト
        assert profile.get_action_for_column("名前", pii_type="name") == "replace"

    def test_update_column_rule(self):
        """列ルールの更新"""
        profile = Profile(name="test")
        old_updated = profile.updated_at

        profile.update_column_rule("氏名", "replace")

        assert profile.column_rules["氏名"] == "replace"
        assert profile.updated_at >= old_updated

    def test_mark_used(self):
        """使用日時の記録"""
        profile = Profile(name="test")
        assert profile.last_used_at is None

        profile.mark_used()

        assert profile.last_used_at is not None


class TestProfileManager:
    """ProfileManager クラスのテスト"""

    def test_save_and_load(self, tmp_path):
        """プロファイルの保存と読み込み"""
        manager = ProfileManager(profile_dir=tmp_path)
        profile = Profile(
            name="test_profile",
            column_rules={"氏名": "replace"},
            pii_type_defaults={"name": "replace"},
        )

        # 保存
        path = manager.save(profile)
        assert path.exists()

        # 読み込み
        loaded = manager.load("test_profile")
        assert loaded is not None
        assert loaded.name == "test_profile"
        assert loaded.column_rules == {"氏名": "replace"}

    def test_load_nonexistent(self, tmp_path):
        """存在しないプロファイルの読み込み"""
        manager = ProfileManager(profile_dir=tmp_path)
        loaded = manager.load("nonexistent")
        assert loaded is None

    def test_delete(self, tmp_path):
        """プロファイルの削除"""
        manager = ProfileManager(profile_dir=tmp_path)
        profile = Profile(name="to_delete")
        manager.save(profile)

        assert manager.exists("to_delete")
        assert manager.delete("to_delete")
        assert not manager.exists("to_delete")

    def test_delete_nonexistent(self, tmp_path):
        """存在しないプロファイルの削除"""
        manager = ProfileManager(profile_dir=tmp_path)
        assert not manager.delete("nonexistent")

    def test_list_profiles(self, tmp_path):
        """プロファイル一覧の取得"""
        manager = ProfileManager(profile_dir=tmp_path)

        # 複数プロファイルを保存
        for name in ["profile_a", "profile_b", "profile_c"]:
            profile = Profile(name=name)
            manager.save(profile)

        profiles = manager.list_profiles()
        assert len(profiles) == 3
        names = [p.name for p in profiles]
        assert "profile_a" in names
        assert "profile_b" in names
        assert "profile_c" in names

    def test_list_profiles_sorted_by_usage(self, tmp_path):
        """プロファイル一覧が使用日時でソートされる"""
        manager = ProfileManager(profile_dir=tmp_path)

        # プロファイルを保存（updated_at順）
        p1 = Profile(name="old")
        p1.updated_at = datetime(2020, 1, 1)
        manager.save(p1)

        p2 = Profile(name="new")
        p2.updated_at = datetime(2026, 1, 1)
        manager.save(p2)

        profiles = manager.list_profiles()
        # 新しい順にソートされている
        assert profiles[0].name == "new"
        assert profiles[1].name == "old"

    def test_export_import(self, tmp_path):
        """プロファイルのエクスポートとインポート"""
        manager = ProfileManager(profile_dir=tmp_path)
        profile = Profile(
            name="export_test",
            column_rules={"氏名": "replace", "住所": "generalize"},
            pii_type_defaults={"name": "replace"},
        )
        manager.save(profile)

        # エクスポート
        export_path = tmp_path / "exported.json"
        assert manager.export_profile("export_test", export_path)
        assert export_path.exists()

        # 別のマネージャでインポート
        manager2 = ProfileManager(profile_dir=tmp_path / "other")
        imported = manager2.import_profile(export_path)
        assert imported is not None
        assert imported.name == "export_test"
        assert imported.column_rules == {"氏名": "replace", "住所": "generalize"}

    def test_import_without_overwrite(self, tmp_path):
        """上書きなしでのインポート（既存がある場合）"""
        manager = ProfileManager(profile_dir=tmp_path)

        # 既存プロファイル
        profile = Profile(name="existing")
        manager.save(profile)

        # エクスポートファイルを作成
        export_path = tmp_path / "exported.json"
        with open(export_path, "w") as f:
            json.dump(Profile(name="existing").to_dict(), f)

        # 上書きなしでインポート（失敗するはず）
        result = manager.import_profile(export_path, overwrite=False)
        assert result is None

    def test_import_with_overwrite(self, tmp_path):
        """上書きありでのインポート"""
        manager = ProfileManager(profile_dir=tmp_path)

        # 既存プロファイル
        old_profile = Profile(name="existing", column_rules={"old": "replace"})
        manager.save(old_profile)

        # エクスポートファイルを作成
        export_path = tmp_path / "exported.json"
        new_profile = Profile(name="existing", column_rules={"new": "generalize"})
        with open(export_path, "w") as f:
            json.dump(new_profile.to_dict(), f)

        # 上書きありでインポート
        result = manager.import_profile(export_path, overwrite=True)
        assert result is not None
        assert result.column_rules == {"new": "generalize"}

    def test_create_default_profile(self, tmp_path):
        """デフォルトプロファイルの作成"""
        manager = ProfileManager(profile_dir=tmp_path)
        default = manager.create_default_profile()

        assert default.name == "default"
        assert "name" in default.pii_type_defaults
        assert "phone" in default.pii_type_defaults
        assert "email" in default.pii_type_defaults

    def test_exists(self, tmp_path):
        """プロファイル存在確認"""
        manager = ProfileManager(profile_dir=tmp_path)

        assert not manager.exists("test")

        profile = Profile(name="test")
        manager.save(profile)

        assert manager.exists("test")


class TestCreateProfileFromActions:
    """create_profile_from_actions 関数のテスト"""

    def test_create_from_actions(self):
        """アクションからプロファイル作成"""
        actions = {
            "氏名": ("name", "replace"),
            "住所": ("address", "generalize"),
            "電話番号": ("phone", "replace"),
        }
        profile = create_profile_from_actions("医療データ", actions)

        assert profile.name == "医療データ"
        assert profile.column_rules["氏名"] == "replace"
        assert profile.column_rules["住所"] == "generalize"
        assert profile.column_rules["電話番号"] == "replace"
        assert profile.pii_type_defaults["name"] == "replace"
        assert profile.pii_type_defaults["address"] == "generalize"
        assert profile.pii_type_defaults["phone"] == "replace"


class TestPIITypeMapping:
    """PIIタイプマッピングのテスト"""

    def test_pii_type_to_profile_key(self):
        """PIIタイプからプロファイルキーへの変換"""
        assert pii_type_to_profile_key("NAME") == "name"
        assert pii_type_to_profile_key("PHONE") == "phone"
        assert pii_type_to_profile_key("ADDRESS") == "address"
        assert pii_type_to_profile_key("PATIENT_ID") == "patient_id"

    def test_profile_key_to_pii_type(self):
        """プロファイルキーからPIIタイプへの変換"""
        assert profile_key_to_pii_type("name") == "NAME"
        assert profile_key_to_pii_type("phone") == "PHONE"
        assert profile_key_to_pii_type("address") == "ADDRESS"
        assert profile_key_to_pii_type("patient_id") == "PATIENT_ID"

    def test_roundtrip(self):
        """往復変換"""
        original = "NAME"
        key = pii_type_to_profile_key(original)
        back = profile_key_to_pii_type(key)
        assert back == original
