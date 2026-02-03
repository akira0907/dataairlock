from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TypedDict


class PIIType(str, Enum):
    NAME = "NAME"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    ADDRESS = "ADDRESS"
    MYNUMBER = "MYNUMBER"
    DOB = "DOB"


@dataclass(frozen=True)
class PIIPattern:
    type: PIIType
    patterns: list
    enabled: bool
    priority: int
    context_required: bool = False


@dataclass(frozen=True)
class PIIMatch:
    type: PIIType
    value: str
    start_index: int
    end_index: int


class StoredMappingEntry(TypedDict):
    placeholder: str
    original: str
    type: str
    sourceFile: str


class StoredMapping(TypedDict):
    version: str
    createdAt: str
    updatedAt: str
    sourceFolder: str
    outputFolder: str
    entries: list[StoredMappingEntry]


@dataclass
class MappingEntry:
    placeholder: str
    original: str
    type: PIIType
    source_file: str
    created_at: int


@dataclass
class SessionMapping:
    entries: dict[str, MappingEntry]  # placeholder -> entry
    reverse_index: dict[str, str]  # original (and normalized) -> placeholder
    counters: dict[PIIType, int]

