from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from dataairlock.cli import app


runner = CliRunner()


def test_vscode_compat_flow(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    workspace_root.mkdir(parents=True, exist_ok=True)

    source_folder = workspace_root / "raw"
    source_folder.mkdir(parents=True, exist_ok=True)

    (source_folder / "note.txt").write_text(
        "担当者: 田中太郎（放射線診断）\n電話: 03-1234-5678\nメール: test@example.com\n",
        encoding="utf-8",
    )

    (source_folder / "config.yaml").write_text(
        "担当者: 田中太郎（放射線診断）\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "vscode",
            "anonymize-folder",
            str(source_folder),
            "--workspace-root",
            str(workspace_root),
        ],
    )
    assert result.exit_code == 0

    airlock_base = workspace_root / "airlock"
    output_folder = airlock_base / "raw"
    mapping_path = airlock_base / ".mapping" / "raw.json"

    assert output_folder.exists()
    assert (output_folder / "note.txt").exists()
    assert (output_folder / "config.yaml").exists()
    assert mapping_path.exists()

    mapping_json = json.loads(mapping_path.read_text(encoding="utf-8"))
    placeholder_tanaka = next(
        e["placeholder"]
        for e in mapping_json["entries"]
        if e["type"] == "NAME" and e["original"] == "田中太郎"
    )

    # YAML のクォート後処理が効く（スカラー先頭がプレースホルダーなら全体をクォート）
    yaml_out = (output_folder / "config.yaml").read_text(encoding="utf-8").strip()
    assert yaml_out.startswith("担当者:")
    assert '"' in yaml_out
    assert "[NAME_" in yaml_out
    assert "（放射線診断）" in yaml_out

    # .claudeignore に mapping が含まれる
    claudeignore = (workspace_root / ".claudeignore").read_text(encoding="utf-8")
    assert "airlock/.mapping/" in claudeignore
    assert "raw/" in claudeignore

    # 2回目の anonymize-folder で mapping が再利用され、既存のプレースホルダーが変わらない
    # （ファイル順が変わっても "田中太郎" は同一プレースホルダーを維持）
    (source_folder / "aaa.txt").write_text("担当者: 鈴木花子\n", encoding="utf-8")

    second = runner.invoke(
        app,
        [
            "vscode",
            "anonymize-folder",
            str(source_folder),
            "--workspace-root",
            str(workspace_root),
        ],
    )
    assert second.exit_code == 0

    mapping_json_2 = json.loads(mapping_path.read_text(encoding="utf-8"))
    placeholder_tanaka_2 = next(
        e["placeholder"]
        for e in mapping_json_2["entries"]
        if e["type"] == "NAME" and e["original"] == "田中太郎"
    )
    assert placeholder_tanaka_2 == placeholder_tanaka

    placeholder_suzuki = next(
        e["placeholder"]
        for e in mapping_json_2["entries"]
        if e["type"] == "NAME" and e["original"] == "鈴木花子"
    )
    assert placeholder_suzuki != placeholder_tanaka

    # apply-mapping で復元できる（in-place）
    generated = output_folder / "generated.txt"
    generated.write_text(f"結果: {placeholder_tanaka}\n", encoding="utf-8")

    apply_result = runner.invoke(
        app,
        [
            "vscode",
            "apply-mapping",
            str(generated),
            "-m",
            str(mapping_path),
            "--workspace-root",
            str(workspace_root),
            "--yes",
            "--no-backup",
        ],
    )
    assert apply_result.exit_code == 0

    restored = generated.read_text(encoding="utf-8")
    assert placeholder_tanaka not in restored
    assert "田中太郎" in restored
