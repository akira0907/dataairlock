from __future__ import annotations

import bisect
import re

from dataairlock.vscode_compat.types import PIIMatch, PIIPattern, PIIType

DOB_CONTEXT_KEYWORDS = [
    "生年月日",
    "誕生日",
    "生まれ",
    "出生日",
    "DOB",
    "dob",
    "birthday",
    "birthdate",
    "birth_date",
    "date_of_birth",
    "dateOfBirth",
]

NAME_EXCLUSION_WORDS = [
    "生年月日",
    "誕生日",
    "電話番号",
    "住所",
    "氏名",
    "名前",
    "担当者",
    "作成日",
    "更新日",
    "登録日",
    "開始日",
    "終了日",
    "有効期限",
    "部署名",
    "所属",
    "職種",
    "役職",
    "確定",
    "未確定",
    "仮確定",
    "診断科",
    "診療科",
    "放射線",
    "内科",
    "外科",
    "整形外科",
    "小児科",
    "産婦人科",
    "皮膚科",
    "眼科",
    "耳鼻科",
    "泌尿器科",
    "精神科",
    "心療内科",
    "救急科",
    "麻酔科",
    "病理診断",
    "当直",
    "日付",
    "時刻",
    "備考",
    "連絡先",
    "緊急連絡",
    "予定",
    "実績",
    "状態",
    "種別",
    "区分",
    "分類",
]

YAML_NAME_KEYS = [
    "name",
    "display_name",
    "short_name",
    "full_name",
    "氏名",
    "名前",
    "担当者",
    "姓",
    "名",
]


class PIIDetector:
    def __init__(self, patterns: list[PIIPattern]):
        self.patterns = patterns
        self._cached_header_context: dict[str, bool] = {}

    def detect(self, text: str) -> list[PIIMatch]:
        matches: list[PIIMatch] = []

        dob_context_lines = self._analyze_dob_context(text)
        sorted_patterns = sorted(
            [p for p in self.patterns if p.enabled or p.context_required],
            key=lambda p: p.priority,
        )

        line_starts = self._build_line_starts(text)

        for pii_pattern in sorted_patterns:
            needs_context_check = (not pii_pattern.enabled) and pii_pattern.context_required

            for regex in pii_pattern.patterns:
                for m in regex.finditer(text):
                    if "pii" in m.groupdict() and m.group("pii") is not None:
                        start = m.start("pii")
                        end = m.end("pii")
                        value = m.group("pii")
                    else:
                        start = m.start()
                        end = m.end()
                        value = m.group(0)

                    if needs_context_check and pii_pattern.type == PIIType.DOB:
                        if not self._has_dob_context(text, start, dob_context_lines, line_starts):
                            continue

                    if pii_pattern.type == PIIType.NAME:
                        if self._is_excluded_name(value):
                            continue

                    if not self._overlaps_existing(matches, start, end):
                        matches.append(
                            PIIMatch(
                                type=pii_pattern.type,
                                value=value,
                                start_index=start,
                                end_index=end,
                            )
                        )

        yaml_name_matches = self._detect_yaml_name_fields(text, matches)
        matches.extend(yaml_name_matches)

        return sorted(matches, key=lambda x: x.start_index)

    def _detect_yaml_name_fields(self, text: str, existing: list[PIIMatch]) -> list[PIIMatch]:
        additional: list[PIIMatch] = []

        for key_name in YAML_NAME_KEYS:
            patterns = [
                re.compile(
                    rf"{re.escape(key_name)}:\s*[\"']?([\u4e00-\u9faf]{{2,4}})[\"']?\s*(?:#|$|\n)",
                    re.IGNORECASE | re.MULTILINE,
                ),
                re.compile(
                    rf"{re.escape(key_name)}:\s*[\"']?([ァ-ヶー]{{2,6}})[\"']?\s*(?:#|$|\n)",
                    re.IGNORECASE | re.MULTILINE,
                ),
            ]

            for regex in patterns:
                for m in regex.finditer(text):
                    value = m.group(1)
                    value_start = m.start() + m.group(0).find(value)
                    value_end = value_start + len(value)

                    if self._is_excluded_name(value):
                        continue

                    if self._overlaps_existing(existing, value_start, value_end):
                        continue
                    if self._overlaps_existing(additional, value_start, value_end):
                        continue

                    additional.append(
                        PIIMatch(
                            type=PIIType.NAME,
                            value=value,
                            start_index=value_start,
                            end_index=value_end,
                        )
                    )

        return additional

    def _analyze_dob_context(self, text: str) -> set[int]:
        lines = text.split("\n")
        if not lines:
            return set()

        header_line = lines[0]
        is_csv = "," in header_line
        is_tsv = "\t" in header_line
        if not (is_csv or is_tsv):
            return set()

        delimiter = "," if is_csv else "\t"
        headers = header_line.split(delimiter)
        dob_indices: list[int] = []
        for idx, header in enumerate(headers):
            normalized = header.strip().lower()
            if any(k.lower() in normalized for k in DOB_CONTEXT_KEYWORDS):
                dob_indices.append(idx)

        if not dob_indices:
            return set()

        return set(range(len(lines)))

    def _is_excluded_name(self, value: str) -> bool:
        normalized = value.strip()
        normalized = re.sub(r'^["「『]|["」』]$', "", normalized)
        return normalized in NAME_EXCLUSION_WORDS

    def _build_line_starts(self, text: str) -> list[int]:
        starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                starts.append(i + 1)
        return starts

    def _line_number_for_position(self, pos: int, line_starts: list[int]) -> int:
        # rightmost start <= pos
        return max(0, bisect.bisect_right(line_starts, pos) - 1)

    def _has_dob_context(
        self, text: str, position: int, context_lines: set[int], line_starts: list[int]
    ) -> bool:
        line_no = self._line_number_for_position(position, line_starts)

        if line_no in context_lines:
            return True

        line_end = text.find("\n", line_starts[line_no])
        if line_end == -1:
            line_end = len(text)
        current_line = text[line_starts[line_no] : line_end]
        lower = current_line.lower()
        return any(k.lower() in lower for k in DOB_CONTEXT_KEYWORDS)

    def _overlaps_existing(self, matches: list[PIIMatch], start: int, end: int) -> bool:
        for m in matches:
            if not (end <= m.start_index or start >= m.end_index):
                return True
        return False
