from __future__ import annotations

import re

from dataairlock.vscode_compat.types import PIIPattern, PIIType


DEFAULT_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        type=PIIType.PHONE,
        patterns=[
            re.compile(r"0\d{1,4}-\d{1,4}-\d{4}(?:-\d{1,6})?"),
            re.compile(r"0[789]0-\d{4}-\d{4}"),
            re.compile(r"0\d{9,10}"),
        ],
        enabled=True,
        priority=10,
    ),
    PIIPattern(
        type=PIIType.EMAIL,
        patterns=[re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")],
        enabled=True,
        priority=20,
    ),
    PIIPattern(
        type=PIIType.MYNUMBER,
        patterns=[
            re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}\b"),
            re.compile(r"\b\d{12}\b"),
        ],
        enabled=True,
        priority=30,
    ),
    # 生年月日（デフォルトはコンテキストベース）
    PIIPattern(
        type=PIIType.DOB,
        patterns=[
            re.compile(r"(19|20)\d{2}[/\-](0?[1-9]|1[0-2])[/\-]([12]\d|3[01]|0?[1-9])"),
            re.compile(r"(19|20)\d{2}年(0?[1-9]|1[0-2])月([12]\d|3[01]|0?[1-9])日"),
            re.compile(r"(明治|大正|昭和|平成|令和)\d{1,2}年(0?[1-9]|1[0-2])月([12]\d|3[01]|0?[1-9])日"),
        ],
        enabled=False,
        priority=40,
        context_required=True,
    ),
    PIIPattern(
        type=PIIType.ADDRESS,
        patterns=[
            re.compile(r"〒?\d{3}-\d{4}"),
            re.compile(r"(東京都|北海道|(?:京都|大阪)府|[^\s]{2,3}県)[^\s,、。\n]{2,}"),
        ],
        enabled=True,
        priority=50,
    ),
    PIIPattern(
        type=PIIType.NAME,
        patterns=[
            # 漢字の姓名（スペースあり）
            re.compile(
                r'(?:^|[　\s,"\[])(?P<pii>[\u4e00-\u9faf]{2,4}[　\s][\u4e00-\u9faf]{1,4})(?=[　\s,、。"（(\n\]]|$)'
            ),
            # 漢字の姓名（スペースなし）+ 括弧（所属）
            re.compile(r'(?:^|[,"\s　\[])(?P<pii>[\u4e00-\u9faf]{3,8})(?=[（(])'),
            # 漢字の姓名（クォート内 4-6文字）
            re.compile(r'(?<=["「『])[\u4e00-\u9faf]{4,6}(?=["」』])'),
            # 漢字の姓名（区切り文字に囲まれる）
            re.compile(
                r'(?:^|[　\s,"\[\]{}():,、。#\nはがをにのへとで])(?P<pii>[\u4e00-\u9faf]{3,8})(?=[　\s,"\[\]{}():,、。#\nはがをにのへとで]|$)'
            ),
            # カタカナの姓名（スペースあり）
            re.compile(r"[ァ-ヶー]{2,6}[　\s][ァ-ヶー]{2,6}"),
            # カタカナの姓名（スペースなし、4文字以上）
            re.compile(r"(?<![ァ-ヶー])[ァ-ヶー]{4,10}(?![ァ-ヶー])"),
        ],
        enabled=True,
        priority=100,
    ),
]
