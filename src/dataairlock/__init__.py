"""DataAirlock - 個人情報匿名化ツール

個人情報を匿名化してクラウドLLMに安全に渡すためのツール。

Usage:
    # CLI
    $ dataairlock anonymize data.csv -p password
    $ dataairlock restore anonymized.csv -m mapping.enc -p password

    # TUI (対話型)
    $ dataairlock-tui

    # Python API
    from dataairlock import Anonymizer

    anon = Anonymizer()
    result_df, mapping = anon.anonymize(df, password="secret")
    restored_df = anon.deanonymize(result_df, mapping, password="secret")
"""

__version__ = "0.1.0"

from dataairlock.anonymizer import (
    Anonymizer,
    PIIType,
    anonymize_dataframe,
    deanonymize_dataframe,
    detect_pii_columns,
    detect_pii_values,
    load_mapping,
    save_mapping,
)

__all__ = [
    "__version__",
    "Anonymizer",
    "PIIType",
    "anonymize_dataframe",
    "deanonymize_dataframe",
    "detect_pii_columns",
    "detect_pii_values",
    "load_mapping",
    "save_mapping",
]
