# DataAirlock

個人情報を含むデータを匿名化し、クラウドLLMに安全に渡せる状態に変換するツール。

## 概要

DataAirlockは、ローカルLLM（Ollama）と対話しながら、機密データを安全に匿名化します。

- ローカルLLMによる個人情報（PII）の自動検出
- 可逆的な匿名化（トークン化）
- マッピング情報の安全な保存
- Streamlit WebUIによる直感的な操作

## セットアップ

```bash
# 仮想環境の有効化
source .venv/bin/activate

# 依存関係のインストール
pip install -r requirements.txt

# 開発用インストール
pip install -e ".[dev]"
```

## 使い方

```bash
# Streamlit アプリを起動
streamlit run src/dataairlock/app.py
```

## プロジェクト構成

```
dataairlock/
├── src/dataairlock/
│   ├── app.py          # Streamlit WebUI
│   ├── anonymizer.py   # 匿名化ロジック
│   └── llm_client.py   # Ollama連携
├── tests/              # テスト
├── data/
│   ├── input/          # 入力データ
│   ├── output/         # 匿名化済みデータ
│   └── mappings/       # マッピング情報
└── requirements.txt
```

## 必要条件

- Python 3.10+
- Ollama（ローカルLLM実行用）

## ライセンス

MIT
