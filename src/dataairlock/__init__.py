"""DataAirlock - 個人情報仮名化ツール

個人情報を仮名化してクラウドLLMに安全に渡すためのツール。

Usage:
    # CLI
    $ dataairlock pseudonymize data.csv -p password
    $ dataairlock restore pseudonymized.csv -m mapping.enc -p password

    # TUI (対話型)
    $ dataairlock-tui

    # Python API
    from dataairlock import Pseudonymizer

    pseudonymizer = Pseudonymizer()
    result_df, mapping = pseudonymizer.pseudonymize(df, password="secret")
    restored_df = pseudonymizer.restore(result_df, mapping, password="secret")
"""

__version__ = "0.1.0"

from dataairlock.pseudonymizer import (
    Pseudonymizer,
    PIIType,
    pseudonymize_dataframe,
    restore_dataframe,
    detect_pii_columns,
    detect_pii_values,
    load_mapping,
    save_mapping,
)

__all__ = [
    "__version__",
    "Pseudonymizer",
    "PIIType",
    "pseudonymize_dataframe",
    "restore_dataframe",
    "detect_pii_columns",
    "detect_pii_values",
    "load_mapping",
    "save_mapping",
]
