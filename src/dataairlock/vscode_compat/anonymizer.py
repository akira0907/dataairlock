from __future__ import annotations

import re
import time

from dataairlock.vscode_compat.types import MappingEntry, PIIMatch, PIIType, SessionMapping


def _normalize_name_for_lookup(value: str, pii_type: PIIType) -> str:
    if pii_type == PIIType.NAME:
        return re.sub(r"[\s　]+", "", value)
    return value


class Anonymizer:
    def anonymize(
        self,
        text: str,
        matches: list[PIIMatch],
        mapping: SessionMapping,
        document_uri: str,
        is_yaml_file: bool = False,
    ) -> tuple[str, list[MappingEntry]]:
        new_entries: list[MappingEntry] = []
        result = text
        offset = 0

        for match in matches:
            normalized_value = _normalize_name_for_lookup(match.value, match.type)
            placeholder = mapping.reverse_index.get(match.value) or mapping.reverse_index.get(normalized_value)

            if not placeholder:
                placeholder = self._generate_placeholder(match.type, mapping)
                new_entries.append(
                    MappingEntry(
                        placeholder=placeholder,
                        original=match.value,
                        type=match.type,
                        source_file=document_uri,
                        created_at=int(time.time() * 1000),
                    )
                )

            adjusted_start = match.start_index + offset
            replacement_value = placeholder

            result = (
                result[:adjusted_start]
                + replacement_value
                + result[adjusted_start + len(match.value) :]
            )
            offset += len(replacement_value) - len(match.value)

        if is_yaml_file:
            result = self._post_process_yaml(result)

        return result, new_entries

    def _generate_placeholder(self, pii_type: PIIType, mapping: SessionMapping) -> str:
        current = mapping.counters.get(pii_type, 0)
        new_counter = current + 1
        mapping.counters[pii_type] = new_counter
        return f"[{pii_type.value}_{new_counter:03d}]"

    def _contains_placeholder(self, text: str) -> bool:
        return re.search(r"\[(NAME|PHONE|EMAIL|ADDRESS|MYNUMBER|DOB)_\d{3}\]", text) is not None

    def _post_process_yaml(self, text: str) -> str:
        lines = text.split("\n")
        out: list[str] = []

        in_block_scalar = False
        block_indent = 0

        for line in lines:
            if in_block_scalar:
                if line.strip() == "":
                    out.append(line)
                    continue

                indent = len(re.match(r"^\s*", line).group(0))
                if indent < block_indent:
                    in_block_scalar = False
                else:
                    out.append(line)
                    continue

            if line.lstrip().startswith("#"):
                out.append(line)
                continue

            block_header = re.match(r"^(?P<indent>\s*)(?:-\s+)?[^#]*:\s*[|>][0-9+-]*\s*(?:#.*)?$", line)
            list_block_header = re.match(r"^(?P<indent>\s*)-\s*[|>][0-9+-]*\s*(?:#.*)?$", line)
            if block_header or list_block_header:
                indent = len((block_header or list_block_header).group("indent"))
                in_block_scalar = True
                block_indent = indent + 1
                out.append(line)
                continue

            if not self._contains_placeholder(line):
                out.append(line)
                continue

            code, comment = self._split_yaml_comment(line)
            fixed = self._quote_yaml_scalars_starting_with_placeholder(code)
            out.append(fixed + comment)

        return "\n".join(out)

    def _split_yaml_comment(self, line: str) -> tuple[str, str]:
        in_single = False
        in_double = False
        single_escaped = False
        double_escaped = False

        for i, ch in enumerate(line):
            if in_single:
                if ch == "'" and not single_escaped:
                    if i + 1 < len(line) and line[i + 1] == "'":
                        single_escaped = True
                    else:
                        in_single = False
                elif ch == "'" and single_escaped:
                    single_escaped = False
                continue

            if in_double:
                if double_escaped:
                    double_escaped = False
                    continue
                if ch == "\\":
                    double_escaped = True
                    continue
                if ch == '"':
                    in_double = False
                continue

            if ch == "'":
                in_single = True
                single_escaped = False
                continue

            if ch == '"':
                in_double = True
                double_escaped = False
                continue

            if ch == "#":
                if i == 0 or re.match(r"\s", line[i - 1]):
                    return line[:i], line[i:]

        return line, ""

    def _quote_yaml_scalars_starting_with_placeholder(self, code: str) -> str:
        placeholder_regex = re.compile(r"\[(NAME|PHONE|EMAIL|ADDRESS|MYNUMBER|DOB)_\d{3}\]")
        if not placeholder_regex.search(code):
            return code

        length = len(code)
        in_single_at: list[bool] = [False] * length
        in_double_at: list[bool] = [False] * length
        flow_depth_at: list[int] = [0] * length
        flow_top_at: list[str | None] = [None] * length

        in_single = False
        in_double = False
        single_escaped = False
        double_escaped = False
        flow_stack: list[str] = []

        for i, ch in enumerate(code):
            in_single_at[i] = in_single
            in_double_at[i] = in_double
            flow_depth_at[i] = len(flow_stack)
            flow_top_at[i] = flow_stack[-1] if flow_stack else None

            if in_single:
                if ch == "'" and not single_escaped:
                    if i + 1 < length and code[i + 1] == "'":
                        single_escaped = True
                    else:
                        in_single = False
                elif ch == "'" and single_escaped:
                    single_escaped = False
                continue

            if in_double:
                if double_escaped:
                    double_escaped = False
                    continue
                if ch == "\\":
                    double_escaped = True
                    continue
                if ch == '"':
                    in_double = False
                continue

            if ch == "'":
                in_single = True
                single_escaped = False
                continue

            if ch == '"':
                in_double = True
                double_escaped = False
                continue

            if ch in ["[", "{"]:
                flow_stack.append(ch)
                continue

            if ch in ["]", "}"]:
                expected = "[" if ch == "]" else "{"
                if flow_stack and flow_stack[-1] == expected:
                    flow_stack.pop()
                continue

        def get_block_content_start() -> int:
            idx = 0
            while idx < length and code[idx].isspace():
                idx += 1
            if idx < length and code[idx] == "-" and (idx + 1 >= length or code[idx + 1].isspace()):
                idx += 1
                while idx < length and code[idx].isspace():
                    idx += 1
            return idx

        def find_block_mapping_separator(from_idx: int) -> int:
            for i in range(from_idx, length):
                if in_single_at[i] or in_double_at[i]:
                    continue
                if flow_depth_at[i] != 0:
                    continue
                if code[i] == ":" and (i + 1 >= length or code[i + 1].isspace()):
                    return i
            return -1

        def find_flow_scalar_start(pos: int, depth: int, container: str | None) -> int:
            for i in range(pos - 1, -1, -1):
                if in_single_at[i] or in_double_at[i]:
                    continue
                ch = code[i]
                if ch == "," and flow_depth_at[i] == depth:
                    s = i + 1
                    while s < length and code[s].isspace():
                        s += 1
                    return s
                if ch in ["[", "{"] and flow_depth_at[i] == depth - 1:
                    s = i + 1
                    while s < length and code[s].isspace():
                        s += 1
                    return s
                if container == "{" and ch == ":" and flow_depth_at[i] == depth:
                    s = i + 1
                    while s < length and code[s].isspace():
                        s += 1
                    return s
            return 0

        def find_flow_scalar_end(pos_after: int, depth: int, container: str | None) -> int:
            for i in range(pos_after, length):
                if in_single_at[i] or in_double_at[i]:
                    continue
                ch = code[i]
                if ch == "," and flow_depth_at[i] == depth:
                    return i
                if ch in ["]", "}"] and flow_depth_at[i] == depth:
                    return i
                if container == "{" and ch == ":" and flow_depth_at[i] == depth:
                    return i
            return length

        ranges: list[tuple[int, int]] = []
        for m in placeholder_regex.finditer(code):
            start = m.start()
            end = m.end()
            if in_single_at[start] or in_double_at[start]:
                continue

            depth = flow_depth_at[start]
            container = flow_top_at[start]

            if depth > 0:
                scalar_start = find_flow_scalar_start(start, depth, container)
                if scalar_start != start:
                    continue
                scalar_end = find_flow_scalar_end(end, depth, container)
            else:
                content_start = get_block_content_start()
                colon_index = find_block_mapping_separator(content_start)
                if colon_index != -1:
                    if start > colon_index:
                        scalar_start = colon_index + 1
                        while scalar_start < length and code[scalar_start].isspace():
                            scalar_start += 1
                        if scalar_start != start:
                            continue
                        scalar_end = length
                    else:
                        scalar_start = content_start
                        if scalar_start != start:
                            continue
                        scalar_end = colon_index
                else:
                    scalar_start = content_start
                    if scalar_start != start:
                        continue
                    scalar_end = length

            if scalar_start < length and code[scalar_start] in ['"', "'"]:
                continue

            trim_end = scalar_end
            while trim_end > scalar_start and code[trim_end - 1].isspace():
                trim_end -= 1

            ranges.append((scalar_start, trim_end))

        if not ranges:
            return code

        unique = sorted(set(ranges), key=lambda r: r[0], reverse=True)
        updated = code
        for start, end in unique:
            segment = updated[start:end]
            quoted = self._quote_yaml_string(segment)
            updated = updated[:start] + quoted + updated[end:]

        return updated

    def _quote_yaml_string(self, value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
