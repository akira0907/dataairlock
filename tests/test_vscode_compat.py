from __future__ import annotations

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

    # apply-mapping で復元できる（in-place）
    generated = output_folder / "generated.txt"
    generated.write_text("結果: [NAME_001]\n", encoding="utf-8")

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
    assert "[NAME_001]" not in restored
    assert "田中太郎" in restored
