from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from dataairlock.vscode_compat.types import MappingEntry, PIIType, SessionMapping, StoredMapping


class MappingStorage:
    VERSION = "1.0.0"

    @staticmethod
    def mapping_dir(airlock_base: Path) -> Path:
        return airlock_base / ".mapping"

    @classmethod
    def mapping_path(cls, airlock_base: Path, source_name: str) -> Path:
        return cls.mapping_dir(airlock_base) / f"{source_name}.json"

    @classmethod
    def save_mapping(
        cls,
        airlock_base: Path,
        source_name: str,
        source_folder: Path,
        output_folder: Path,
        mapping: SessionMapping,
    ) -> Path:
        mapping_dir = cls.mapping_dir(airlock_base)
        mapping_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc).isoformat()

        stored: StoredMapping = {
            "version": cls.VERSION,
            "createdAt": now,
            "updatedAt": now,
            "sourceFolder": str(source_folder),
            "outputFolder": str(output_folder),
            "entries": [
                {
                    "placeholder": e.placeholder,
                    "original": e.original,
                    "type": e.type.value,
                    "sourceFile": e.source_file,
                }
                for e in mapping.entries.values()
            ],
        }

        path = cls.mapping_path(airlock_base, source_name)
        path.write_text(json.dumps(stored, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load_mapping(cls, mapping_path: Path) -> SessionMapping:
        stored = json.loads(mapping_path.read_text(encoding="utf-8"))
        entries: dict[str, MappingEntry] = {}
        reverse_index: dict[str, str] = {}
        counters: dict[PIIType, int] = {t: 0 for t in PIIType}

        for item in stored.get("entries", []):
            placeholder = item["placeholder"]
            original = item["original"]
            pii_type = PIIType(item["type"])
            source_file = item.get("sourceFile", "")
            entry = MappingEntry(
                placeholder=placeholder,
                original=original,
                type=pii_type,
                source_file=source_file,
                created_at=0,
            )
            entries[placeholder] = entry
            reverse_index[original] = placeholder

            if pii_type == PIIType.NAME:
                normalized = "".join(original.split()).replace("　", "")
                if normalized and normalized != original:
                    reverse_index[normalized] = placeholder

            m = re.match(r"\[([A-Z]+)_(\d+)\]", placeholder)
            if m:
                t = PIIType(m.group(1))
                num = int(m.group(2))
                counters[t] = max(counters.get(t, 0), num)

        return SessionMapping(entries=entries, reverse_index=reverse_index, counters=counters)
