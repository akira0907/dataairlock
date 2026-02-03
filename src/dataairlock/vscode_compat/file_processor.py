from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dataairlock.vscode_compat.anonymizer import Anonymizer, _normalize_name_for_lookup
from dataairlock.vscode_compat.mapping_storage import MappingStorage
from dataairlock.vscode_compat.pii_detector import PIIDetector
from dataairlock.vscode_compat.types import MappingEntry, PIIType, SessionMapping


DEFAULT_EXTENSIONS = [
    ".txt",
    ".md",
    ".csv",
    ".json",
    ".xml",
    ".html",
    ".htm",
    ".log",
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".rb",
    ".go",
    ".rs",
    ".swift",
    ".yaml",
    ".yml",
]

DEFAULT_EXCLUDE_DIRS = {
    "node_modules",
    ".git",
    ".vscode",
    ".venv",
    "venv",
    "__pycache__",
    "airlock",
    ".airlock",
    ".airlock_mappings",
    "dist",
    "out",
}


@dataclass
class ProcessResult:
    files_processed: int
    pii_found: int
    output_folder: Path
    mapping_path: Path | None
    errors: list[str]


@dataclass
class ApplyMappingResult:
    files_processed: int
    replaced_count: int
    errors: list[str]


class FileProcessor:
    def __init__(self, detector: PIIDetector, anonymizer: Anonymizer):
        self.detector = detector
        self.anonymizer = anonymizer

    def _is_yaml_file(self, path: Path) -> bool:
        return path.suffix.lower() in {".yaml", ".yml"}

    def _is_target_file(self, path: Path, extensions: list[str]) -> bool:
        return path.suffix.lower() in set(extensions)

    def _iter_files(self, source_folder: Path) -> list[Path]:
        files: list[Path] = []
        for root, dirnames, filenames in os.walk(source_folder):
            dirnames[:] = sorted([d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS])
            for name in sorted(filenames):
                files.append(Path(root) / name)
        return files

    def anonymize_folder(
        self,
        workspace_root: Path,
        source_folder: Path,
        airlock_folder_name: str = "airlock",
        source_name: str | None = None,
        extensions: list[str] | None = None,
        hide_original: bool = True,
    ) -> ProcessResult:
        extensions = extensions or DEFAULT_EXTENSIONS
        source_name = source_name or source_folder.name
        airlock_base = workspace_root / airlock_folder_name
        output_folder = airlock_base / source_name
        output_folder.mkdir(parents=True, exist_ok=True)

        errors: list[str] = []
        files_processed = 0
        pii_found = 0

        mapping = SessionMapping(entries={}, reverse_index={}, counters={t: 0 for t in PIIType})
        existing_mapping_path = MappingStorage.mapping_path(airlock_base, source_name)
        if existing_mapping_path.exists():
            try:
                mapping = MappingStorage.load_mapping(existing_mapping_path)
            except Exception as e:
                errors.append(f"{existing_mapping_path}: 既存マッピングの読み込みに失敗: {e}")
                mapping = SessionMapping(entries={}, reverse_index={}, counters={t: 0 for t in PIIType})

        for file_path in self._iter_files(source_folder):
            try:
                if not file_path.is_file():
                    continue
                if not self._is_target_file(file_path, extensions):
                    continue

                rel = file_path.relative_to(source_folder)
                out_path = output_folder / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)

                content = file_path.read_text(encoding="utf-8")
                matches = self.detector.detect(content)
                pii_found += len(matches)

                if matches:
                    anonymized, new_entries = self.anonymizer.anonymize(
                        content,
                        matches,
                        mapping,
                        document_uri=str(file_path),
                        is_yaml_file=self._is_yaml_file(file_path),
                    )

                    for entry in new_entries:
                        mapping.entries[entry.placeholder] = entry
                        mapping.reverse_index[entry.original] = entry.placeholder
                        normalized = _normalize_name_for_lookup(entry.original, entry.type)
                        if normalized != entry.original:
                            mapping.reverse_index[normalized] = entry.placeholder

                    out_path.write_text(anonymized, encoding="utf-8")
                else:
                    out_path.write_text(content, encoding="utf-8")

                files_processed += 1
            except Exception as e:
                errors.append(f"{file_path}: {e}")

        mapping_path = None
        if mapping.entries:
            mapping_path = MappingStorage.save_mapping(
                airlock_base=airlock_base,
                source_name=source_name,
                source_folder=source_folder,
                output_folder=output_folder,
                mapping=mapping,
            )

        return ProcessResult(
            files_processed=files_processed,
            pii_found=pii_found,
            output_folder=output_folder,
            mapping_path=mapping_path,
            errors=errors,
        )

    def apply_mapping(
        self,
        target_path: Path,
        mapping_path: Path,
        extensions: list[str] | None = None,
        in_place: bool = True,
        backup: bool = True,
    ) -> ApplyMappingResult:
        extensions = extensions or DEFAULT_EXTENSIONS
        errors: list[str] = []

        mapping = MappingStorage.load_mapping(mapping_path)
        placeholder_map = {p: e.original for p, e in mapping.entries.items()}

        files_processed = 0
        replaced_count = 0

        def apply_to_file(path: Path) -> None:
            nonlocal files_processed, replaced_count

            if not self._is_target_file(path, extensions):
                return

            try:
                content = path.read_text(encoding="utf-8")
            except Exception as e:
                errors.append(f"{path}: {e}")
                return

            new_content = content
            file_replaced = 0
            for placeholder, original in placeholder_map.items():
                c = new_content.count(placeholder)
                if c:
                    new_content = new_content.replace(placeholder, original)
                    file_replaced += c

            if file_replaced == 0:
                files_processed += 1
                return

            try:
                if in_place:
                    if backup:
                        backup_path = path.with_suffix(path.suffix + ".bak")
                        if not backup_path.exists():
                            backup_path.write_text(content, encoding="utf-8")
                    path.write_text(new_content, encoding="utf-8")
                else:
                    # 非破壊モード: target_path の隣に restored/ を作り相対パスを維持
                    base = target_path if target_path.is_dir() else target_path.parent
                    out_base = base / "restored"
                    rel = path.relative_to(base)
                    out_path = out_base / rel
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(new_content, encoding="utf-8")

                files_processed += 1
                replaced_count += file_replaced
            except Exception as e:
                errors.append(f"{path}: {e}")

        if target_path.is_file():
            apply_to_file(target_path)
        else:
            for file_path in self._iter_files(target_path):
                if file_path.is_file():
                    apply_to_file(file_path)

        return ApplyMappingResult(
            files_processed=files_processed,
            replaced_count=replaced_count,
            errors=errors,
        )
