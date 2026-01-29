"""Streamlit WebUI メインアプリケーション"""

import io
from datetime import datetime

import pandas as pd
import streamlit as st

from dataairlock.anonymizer import (
    Confidence,
    PIIType,
    anonymize_dataframe,
    deanonymize_dataframe,
    detect_pii_columns,
    load_mapping,
    PIIColumnResult,
)


def load_file(uploaded_file) -> pd.DataFrame | None:
    """アップロードされたファイルをDataFrameとして読み込む"""
    if uploaded_file is None:
        return None

    try:
        if uploaded_file.name.endswith(".csv"):
            return pd.read_csv(uploaded_file)
        elif uploaded_file.name.endswith((".xlsx", ".xls")):
            return pd.read_excel(uploaded_file)
        else:
            st.error("サポートされていないファイル形式です。CSV または Excel ファイルをアップロードしてください。")
            return None
    except Exception as e:
        st.error(f"ファイルの読み込みに失敗しました: {e}")
        return None


def get_confidence_badge(confidence: Confidence) -> str:
    """確度に応じたバッジを返す"""
    if confidence == Confidence.HIGH:
        return "🔴 高"
    elif confidence == Confidence.MEDIUM:
        return "🟡 中"
    else:
        return "🟢 低"


def get_pii_type_label(pii_type: PIIType) -> str:
    """PIIタイプのラベルを返す"""
    return pii_type.value


def dataframe_to_csv_bytes(df: pd.DataFrame) -> bytes:
    """DataFrameをUTF-8 BOM付きCSVバイト列に変換（Excel対応）"""
    csv_buffer = io.BytesIO()
    # UTF-8 BOMを書き込み（Excelで文字化けしないため）
    csv_buffer.write(b'\xef\xbb\xbf')
    csv_buffer.write(df.to_csv(index=False).encode('utf-8'))
    return csv_buffer.getvalue()


def generate_llm_prompt(
    filename: str,
    columns_info: list[dict],
    anonymized_columns: list[str],
) -> str:
    """LLM用プロンプトを生成"""
    prompt = f"""以下は匿名化済みの医療データ「{filename}」です。

## データ概要
このデータは個人情報保護のため、以下の列が匿名化されています：

| 列名 | 匿名化方法 |
|------|-----------|
"""
    for info in columns_info:
        prompt += f"| {info['列名']} | {info['処理']} |\n"

    prompt += f"""
## 注意事項
- `ANON_` で始まる値は匿名化されたIDです。同じIDは同一の元データを指します
- 一般化された値（年代、都道府県など）は元の詳細情報を含みません
- 削除された列は復元できません

## 分析依頼
このデータを分析して、以下の点について教えてください：

1. [ここに分析してほしい内容を記入]
2. [追加の分析項目]

※ 分析結果に `ANON_` IDが含まれる場合、そのまま出力してください。
"""
    return prompt


def render_anonymize_mode():
    """匿名化モードのUI"""
    # セッション状態の初期化
    if "df" not in st.session_state:
        st.session_state.df = None
    if "pii_columns" not in st.session_state:
        st.session_state.pii_columns = {}
    if "anonymized_df" not in st.session_state:
        st.session_state.anonymized_df = None
    if "mapping" not in st.session_state:
        st.session_state.mapping = None

    # ========== Step 1: ファイルアップロード ==========
    st.header("📁 Step 1: ファイルアップロード")

    uploaded_file = st.file_uploader(
        "CSV または Excel ファイルをアップロード",
        type=["csv", "xlsx", "xls"],
        help="個人情報を含むデータファイルをアップロードしてください",
        key="anonymize_upload",
    )

    if uploaded_file is not None:
        df = load_file(uploaded_file)
        if df is not None:
            st.session_state.df = df
            st.session_state.filename = uploaded_file.name

            # PII検出
            st.session_state.pii_columns = detect_pii_columns(df)

            # リセット
            st.session_state.anonymized_df = None
            st.session_state.mapping = None

    # データがある場合の処理
    if st.session_state.df is not None:
        df = st.session_state.df
        pii_columns = st.session_state.pii_columns

        # データプレビュー
        st.subheader("📊 データプレビュー（先頭5行）")

        # PII列をハイライト
        def highlight_pii_columns(col):
            if col.name in pii_columns:
                return ["background-color: #fff3cd"] * len(col)
            return [""] * len(col)

        styled_df = df.head().style.apply(highlight_pii_columns)
        st.dataframe(styled_df, width='stretch')

        st.caption(f"総行数: {len(df):,} 行 | 総列数: {len(df.columns)} 列")

        # ========== Step 2: PII検出結果 ==========
        st.header("🔍 Step 2: PII検出結果")

        if not pii_columns:
            st.success("個人情報と思われる列は検出されませんでした。")
        else:
            st.warning(f"⚠️ {len(pii_columns)} 件の個人情報列を検出しました")

            # 検出結果テーブル
            detection_data = []
            for col_name, result in pii_columns.items():
                # 日付列へのサジェスト
                note = ""
                if result.pii_type == PIIType.BIRTHDATE:
                    note = "💡 生年月日以外の日付の場合は「スキップ」を選択してください"

                detection_data.append({
                    "列名": f"⚠️ {col_name}",
                    "検出タイプ": get_pii_type_label(result.pii_type),
                    "確度": get_confidence_badge(result.confidence),
                    "検出方法": "列名パターン" if result.matched_by == "column_name" else "データ内容",
                    "サンプル値": ", ".join(result.sample_values[:3]) if result.sample_values else "-",
                    "備考": note,
                })

            st.dataframe(
                pd.DataFrame(detection_data),
                width='stretch',
                hide_index=True,
            )

            # 日付検出の注意書き
            if any(r.pii_type == PIIType.BIRTHDATE for r in pii_columns.values()):
                st.info("💡 **日付形式の列について**: 生年月日以外の日付（診察日、処方日など）が検出される場合があります。個人を特定できない日付は「スキップ」を選択してください。")

        # ========== Step 3: 処理方法の選択 ==========
        st.header("⚙️ Step 3: 処理方法の選択")

        # 各列の処理方法
        column_actions: dict[str, str] = {}

        if pii_columns:
            st.markdown("各列の匿名化方法を選択してください:")

            cols = st.columns(2)

            for i, (col_name, result) in enumerate(pii_columns.items()):
                with cols[i % 2]:
                    # 一般化が効果的な列にはデフォルトで generalize を選択
                    default_idx = 0
                    if result.pii_type in [PIIType.BIRTHDATE, PIIType.ADDRESS, PIIType.AGE]:
                        default_idx = 1  # generalize

                    action = st.selectbox(
                        f"**{col_name}** ({result.pii_type.value})",
                        options=["replace", "generalize", "delete", "skip"],
                        index=default_idx,
                        format_func=lambda x: {
                            "replace": "🔄 置換（ランダムID）",
                            "generalize": "📊 一般化（年代・都道府県等）",
                            "delete": "🗑️ 削除",
                            "skip": "⏭️ スキップ（処理しない）",
                        }[x],
                        key=f"action_{col_name}",
                        help=f"サンプル: {', '.join(result.sample_values[:2]) if result.sample_values else 'N/A'}",
                    )
                    column_actions[col_name] = action

        # ========== Step 4: パスワード入力 ==========
        st.header("🔑 Step 4: パスワード設定")

        password = st.text_input(
            "マッピングファイル暗号化用パスワード",
            type="password",
            help="復元時に必要になります。安全な場所に保管してください。",
            key="anon_password",
        )

        password_confirm = st.text_input(
            "パスワード（確認）",
            type="password",
            key="anon_password_confirm",
        )

        # パスワードバリデーション
        password_valid = False
        if password and password_confirm:
            if password != password_confirm:
                st.error("パスワードが一致しません")
            elif len(password) < 8:
                st.warning("パスワードは8文字以上を推奨します")
                password_valid = True
            else:
                st.success("パスワードが設定されました")
                password_valid = True

        # ========== Step 5: 実行 ==========
        st.header("🚀 Step 5: 匿名化実行")

        # 実行可能条件のチェック
        can_execute = (
            st.session_state.df is not None
            and password_valid
            and any(action != "skip" for action in column_actions.values())
        )

        if not can_execute:
            if not password_valid:
                st.info("パスワードを入力してください")
            elif not any(action != "skip" for action in column_actions.values()):
                st.info("少なくとも1つの列を処理対象にしてください")

        if st.button("🔒 匿名化を実行", disabled=not can_execute, type="primary", key="run_anonymize"):
            with st.spinner("匿名化処理中..."):
                # 処理対象の列を抽出
                columns_to_process = {
                    col: result
                    for col, result in pii_columns.items()
                    if column_actions.get(col, "skip") != "skip"
                }

                # 戦略ごとに分けて処理
                anonymized_df = df.copy()
                full_mapping: dict = {
                    "metadata": {
                        "created_at": datetime.now().isoformat(),
                        "original_file": st.session_state.filename,
                        "columns_processed": list(columns_to_process.keys()),
                    }
                }

                for col_name, result in columns_to_process.items():
                    action = column_actions[col_name]

                    # 単一列のPII結果を作成
                    single_col_pii = {col_name: result}

                    # 匿名化実行
                    anonymized_df, col_mapping = anonymize_dataframe(
                        anonymized_df,
                        single_col_pii,
                        strategy=action,  # type: ignore
                    )

                    # マッピングをマージ
                    if col_name in col_mapping:
                        full_mapping[col_name] = col_mapping[col_name]

                st.session_state.anonymized_df = anonymized_df
                st.session_state.mapping = full_mapping
                st.session_state.password = password
                st.session_state.column_actions = column_actions

            st.success("✅ 匿名化が完了しました！")

        # ========== Step 6: 結果表示 & ダウンロード ==========
        if st.session_state.anonymized_df is not None:
            st.header("📋 Step 6: 結果確認 & ダウンロード")

            # 比較表示
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("📄 元データ（先頭5行）")
                st.dataframe(df.head(), width='stretch')

            with col2:
                st.subheader("🔒 匿名化後（先頭5行）")
                st.dataframe(st.session_state.anonymized_df.head(), width='stretch')

            # 処理サマリー
            st.subheader("📊 処理サマリー")
            mapping = st.session_state.mapping

            summary_data = []
            for col_name, col_info in mapping.items():
                if col_name == "metadata":
                    continue
                action = col_info.get("action", "unknown")
                pii_type = col_info.get("pii_type", "不明")
                values_count = len(col_info.get("values", {}))

                summary_data.append({
                    "列名": col_name,
                    "PIIタイプ": pii_type,
                    "処理": {
                        "replaced": "🔄 置換",
                        "generalized": "📊 一般化",
                        "deleted": "🗑️ 削除",
                    }.get(action, action),
                    "処理件数": f"{values_count} 件" if action != "deleted" else "-",
                })

            st.dataframe(
                pd.DataFrame(summary_data),
                width='stretch',
                hide_index=True,
            )

            # ダウンロードボタン
            st.subheader("💾 ダウンロード")

            col1, col2 = st.columns(2)

            with col1:
                # 匿名化CSVのダウンロード（UTF-8 BOM付き）
                csv_data = dataframe_to_csv_bytes(st.session_state.anonymized_df)

                st.download_button(
                    label="📥 匿名化データをダウンロード (CSV)",
                    data=csv_data,
                    file_name="anonymized.csv",
                    mime="text/csv",
                )

            with col2:
                # マッピングファイルのダウンロード
                import json
                import base64
                import hashlib
                from cryptography.fernet import Fernet

                mapping_buffer = io.BytesIO()

                password = st.session_state.password
                salt = hashlib.sha256(password.encode()).digest()[:16]
                key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)
                fernet_key = base64.urlsafe_b64encode(key)
                fernet = Fernet(fernet_key)

                json_data = json.dumps(mapping, ensure_ascii=False, indent=2)
                encrypted_data = fernet.encrypt(json_data.encode("utf-8"))

                mapping_buffer.write(salt + encrypted_data)
                mapping_data = mapping_buffer.getvalue()

                st.download_button(
                    label="🔐 マッピングファイルをダウンロード (暗号化)",
                    data=mapping_data,
                    file_name="mapping.enc",
                    mime="application/octet-stream",
                )

            st.info("⚠️ マッピングファイルは復元に必要です。パスワードと共に安全に保管してください。")

            # ========== LLM用プロンプト生成 ==========
            st.subheader("🤖 Claude Code 用プロンプト")

            llm_prompt = generate_llm_prompt(
                filename=st.session_state.filename,
                columns_info=summary_data,
                anonymized_columns=[d["列名"] for d in summary_data],
            )

            st.text_area(
                "以下のプロンプトをコピーして、匿名化CSVと一緒にClaude Codeに渡してください：",
                value=llm_prompt,
                height=400,
                key="llm_prompt",
            )

            # コピーボタン（Streamlitの制限でJavaScriptは使えないが、text_areaで選択可能）
            st.caption("💡 上のテキストエリアをクリックして Ctrl+A → Ctrl+C でコピーできます")

    else:
        # ファイル未アップロード時のガイダンス
        st.info("👆 ファイルをアップロードして開始してください")

        with st.expander("📖 使い方"):
            st.markdown("""
            ### DataAirlock の使い方

            1. **ファイルアップロード**: 個人情報を含むCSVまたはExcelファイルをアップロード
            2. **PII検出確認**: 自動検出された個人情報列を確認
            3. **処理方法選択**: 各列の匿名化方法を選択
               - **置換**: ランダムIDに置換（復元可能）
               - **一般化**: 生年月日→年代、住所→都道府県など
               - **削除**: 列を完全に削除
               - **スキップ**: 処理しない
            4. **パスワード設定**: マッピングファイルの暗号化用
            5. **実行**: 匿名化を実行
            6. **ダウンロード**: 匿名化データとマッピングファイルを取得

            ### 対応する個人情報

            - 患者ID / カルテ番号
            - 氏名（漢字・カナ）
            - 生年月日 / 年齢
            - 電話番号
            - メールアドレス
            - 住所
            - マイナンバー
            """)


def render_restore_mode():
    """復元モードのUI"""
    st.header("🔓 データ復元")
    st.markdown("Claude Code等から返ってきた結果を元のデータに復元します。")

    # セッション状態の初期化
    if "restore_df" not in st.session_state:
        st.session_state.restore_df = None
    if "restore_mapping" not in st.session_state:
        st.session_state.restore_mapping = None
    if "restored_df" not in st.session_state:
        st.session_state.restored_df = None

    # ========== Step 1: 結果ファイルアップロード ==========
    st.subheader("📁 Step 1: 結果ファイルをアップロード")

    result_file = st.file_uploader(
        "Claude Code等から返ってきたCSVファイル",
        type=["csv"],
        help="ANON_xxxを含む結果ファイルをアップロードしてください",
        key="restore_result_upload",
    )

    if result_file is not None:
        try:
            st.session_state.restore_df = pd.read_csv(result_file)
            st.session_state.restore_filename = result_file.name
        except Exception as e:
            st.error(f"ファイルの読み込みに失敗しました: {e}")

    # ========== Step 2: マッピングファイルアップロード ==========
    st.subheader("🔐 Step 2: マッピングファイルをアップロード")

    mapping_file = st.file_uploader(
        "匿名化時に保存したmapping.encファイル",
        type=["enc"],
        help="匿名化時にダウンロードしたマッピングファイル",
        key="restore_mapping_upload",
    )

    # ========== Step 3: パスワード入力 ==========
    st.subheader("🔑 Step 3: パスワード入力")

    restore_password = st.text_input(
        "マッピングファイルのパスワード",
        type="password",
        help="匿名化時に設定したパスワード",
        key="restore_password",
    )

    # マッピング読み込み
    if mapping_file is not None and restore_password:
        try:
            mapping_bytes = mapping_file.read()
            mapping_file.seek(0)  # リセット

            # 一時ファイルに書き込んでload_mappingを使う
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
                tmp.write(mapping_bytes)
                tmp_path = tmp.name

            st.session_state.restore_mapping = load_mapping(tmp_path, restore_password)
            st.success("✅ マッピングファイルの読み込みに成功しました")

            # マッピング情報を表示
            with st.expander("📋 マッピング情報"):
                metadata = st.session_state.restore_mapping.get("metadata", {})
                st.write(f"- 作成日時: {metadata.get('created_at', '不明')}")
                st.write(f"- 元ファイル: {metadata.get('original_file', '不明')}")
                st.write(f"- 処理列: {', '.join(metadata.get('columns_processed', []))}")

        except ValueError as e:
            st.error(f"❌ {e}")
            st.session_state.restore_mapping = None
        except Exception as e:
            st.error(f"❌ マッピングファイルの読み込みに失敗しました: {e}")
            st.session_state.restore_mapping = None

    # プレビュー
    if st.session_state.restore_df is not None:
        st.subheader("📊 結果ファイルプレビュー（先頭5行）")
        st.dataframe(st.session_state.restore_df.head(), width='stretch')
        st.caption(f"総行数: {len(st.session_state.restore_df):,} 行 | 総列数: {len(st.session_state.restore_df.columns)} 列")

    # ========== Step 4: 復元実行 ==========
    st.subheader("🚀 Step 4: 復元実行")

    can_restore = (
        st.session_state.restore_df is not None
        and st.session_state.restore_mapping is not None
    )

    if not can_restore:
        if st.session_state.restore_df is None:
            st.info("結果ファイルをアップロードしてください")
        elif st.session_state.restore_mapping is None:
            st.info("マッピングファイルをアップロードし、パスワードを入力してください")

    if st.button("🔓 復元を実行", disabled=not can_restore, type="primary", key="run_restore"):
        with st.spinner("復元処理中..."):
            restored_df = deanonymize_dataframe(
                st.session_state.restore_df,
                st.session_state.restore_mapping,
            )
            st.session_state.restored_df = restored_df

        st.success("✅ 復元が完了しました！")

    # ========== Step 5: 結果表示 & ダウンロード ==========
    if st.session_state.restored_df is not None:
        st.subheader("📋 復元結果")

        # 比較表示
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**📄 復元前（ANON_xxx）**")
            st.dataframe(st.session_state.restore_df.head(), width='stretch')

        with col2:
            st.markdown("**🔓 復元後（元の値）**")
            st.dataframe(st.session_state.restored_df.head(), width='stretch')

        # 復元統計
        st.subheader("📊 復元統計")

        mapping = st.session_state.restore_mapping
        restore_stats = []

        for col_name, col_info in mapping.items():
            if col_name == "metadata":
                continue

            action = col_info.get("action", "unknown")
            values_mapping = col_info.get("values", {})

            if action == "deleted":
                restore_stats.append({
                    "列名": col_name,
                    "元の処理": "🗑️ 削除",
                    "復元状態": "❌ 復元不可",
                })
            else:
                # 復元された値の数をカウント
                if col_name in st.session_state.restore_df.columns:
                    reverse_mapping = {v: k for k, v in values_mapping.items()}
                    restored_count = sum(
                        1 for val in st.session_state.restore_df[col_name]
                        if str(val) in reverse_mapping
                    )
                    restore_stats.append({
                        "列名": col_name,
                        "元の処理": {"replaced": "🔄 置換", "generalized": "📊 一般化"}.get(action, action),
                        "復元状態": f"✅ {restored_count} 件復元",
                    })
                else:
                    restore_stats.append({
                        "列名": col_name,
                        "元の処理": {"replaced": "🔄 置換", "generalized": "📊 一般化"}.get(action, action),
                        "復元状態": "⚠️ 列が存在しない",
                    })

        if restore_stats:
            st.dataframe(
                pd.DataFrame(restore_stats),
                width='stretch',
                hide_index=True,
            )

        # ダウンロード
        st.subheader("💾 ダウンロード")

        csv_data = dataframe_to_csv_bytes(st.session_state.restored_df)

        st.download_button(
            label="📥 復元データをダウンロード (CSV)",
            data=csv_data,
            file_name="restored.csv",
            mime="text/csv",
        )


def main():
    st.set_page_config(
        page_title="DataAirlock",
        page_icon="🔒",
        layout="wide",
    )

    st.title("🔒 DataAirlock")
    st.markdown("個人情報を匿名化してクラウドLLMに安全に渡すためのツール")

    # タブで匿名化/復元を切り替え
    tab1, tab2 = st.tabs(["🔒 匿名化", "🔓 復元"])

    with tab1:
        render_anonymize_mode()

    with tab2:
        render_restore_mode()


if __name__ == "__main__":
    main()
