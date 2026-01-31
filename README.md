<p align="center">
  <img src="assets/logo.png" alt="DataAirlock Logo" width="300">
</p>

<h1 align="center">DataAirlock</h1>

<p align="center">
  <a href="https://pypi.org/project/dataairlock/"><img src="https://img.shields.io/pypi/v/dataairlock" alt="PyPI version"></a>
  <a href="https://pypi.org/project/dataairlock/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python"></a>
  <img src="https://img.shields.io/badge/license-AGPL%20v3.0-green" alt="License">
  <img src="https://img.shields.io/badge/security-local--only-brightgreen" alt="Security">
  <img src="https://img.shields.io/badge/status-beta-orange" alt="Status">
</p>

<p align="center"><strong>LLMを安全に使うためのローカル仮名化パイプライン</strong></p>

[English Documentation](./README_en.md) | [不具合報告](https://github.com/akira0907/dataairlock/issues)

---

## 課題

**機密データをLLMに送信することはできません。**

患者記録、顧客情報、社内文書——ChatGPTやClaudeなどのクラウドAIに送信した時点で、データの管理権を失います。GDPRはこれを禁止しています。個人情報保護法もこれを禁止しています。御社のセキュリティポリシーもこれを禁止しているはずです。

**DataAirlockは、LLM使用前にデータをローカルで仮名化することでこの課題を解決します。**

個人情報は可逆的なセマンティックトークン（例：`PERSON_001`）に置換されます。暗号化されたマッピングはローカルに保存されます。LLM処理後、データを元の形式に復元できます。これはGDPRに準拠した仮名化（pseudonymization）であり、不可逆的な匿名化（anonymization）ではありません。

---

## 免責事項

> **本ツールは個人情報の検出・仮名化を100%保証するものではありません。**
> 出力データは必ずユーザー自身の目で確認してください。
> 開発者は本ツール使用によるデータの漏洩や損害について一切の責任を負いません。

---

## 仕組み

```mermaid
flowchart LR
    subgraph Local["ローカル環境（あなたのPC）"]
        A[("機密データ<br/>山田太郎, 090-1234-5678")] --> B["DataAirlock<br/>仮名化"]
        B --> C[("仮名化データ<br/>PERSON_001, PHONE_001")]
        F["DataAirlock<br/>復元"] --> G[("復元済み結果<br/>山田太郎, 090-1234-5678")]
    end

    subgraph Cloud["クラウド LLM"]
        D["Claude Code<br/>Codex, GPT..."]
    end

    C -.->|"安全に送信"| D
    D -.->|"分析結果"| E[("結果<br/>PERSON_001の来院回数...")]
    E --> F

    style A fill:#ffe0e0,stroke:#cc0000
    style G fill:#e0ffe0,stroke:#00cc00
    style C fill:#fff3cd,stroke:#cc9900
    style E fill:#fff3cd,stroke:#cc9900
    style D fill:#e0e0ff,stroke:#0000cc
```

1. **入力** — 個人情報を含むドキュメントやデータセットを読み込む
2. **仮名化** — DataAirlockが個人情報を検出し、セマンティックトークンに置換
3. **処理** — 仮名化されたデータを安全にLLMへ送信
4. **復元** — LLMの出力結果を元のデータに復元

---

## なぜ仮名化（pseudonymization）であり、匿名化（anonymization）ではないのか

| | 匿名化（anonymization） | 仮名化（pseudonymization） |
|---|------------------------|---------------------------|
| **可逆性** | 不可逆 | キーにより復元可能 |
| **元データ** | 永久に失われる | 復元可能 |
| **GDPRでの定義** | 第26条（適用範囲外） | 第4条(5)（リスク軽減措置） |
| **用途** | 公開データセット | 処理ワークフロー |

**DataAirlockは仮名化を行います。** データは復元可能です。これは意図的な設計であり、LLMの処理結果を実際のエンティティにマッピングし直すワークフローに必要な機能です。

---

## 特徴

- **ローカル処理** — 仮名化・復元はすべてローカルで実行。生データがクラウドに送信されることはありません
- **セマンティックトークン** — `PATIENT_001`等の意味のあるIDでLLMが文脈を理解
- **暗号化マッピング** — トークンと元データの対応表はFernet（AES-128-CBC）で暗号化
- **ワンコマンド復元** — 分析結果を元のデータに即座に復元
- **CLI完結** — ターミナルで完結、Claude Code や他のCLIツールとシームレスに連携

---

## クイックスタート

### インストール

```bash
pip install dataairlock
```

オプション機能を含める場合：

```bash
# LLM検出機能（Ollama連携）
pip install dataairlock[ollama]

# Web UI（Streamlit）
pip install dataairlock[streamlit]

# すべての機能
pip install dataairlock[all]
```

### 基本的な使い方

```bash
# 1. ワークスペースを作成（ファイルを仮名化）
dataairlock workspace ./my_project --add data/patients.csv -p mypassword

# 2. Claude Code を起動（仮名化データで作業）
dataairlock wrap ./my_project --shell
# または
cd ./my_project/.airlock && claude

# 3. 結果を復元
dataairlock workspace ./my_project --restore-all -p mypassword
```

### Claude Code との連携

```bash
# 対話シェルを起動（.airlock/ 内で作業）
dataairlock wrap ./my_project --shell

# Claude Code を直接起動
dataairlock wrap ./my_project -c "claude"

# 自動復元付きでスクリプト実行
dataairlock wrap ./my_project -c "python analyze.py" --auto-restore -p mypassword
```

---

## 対応する個人情報（PII）

| PIIタイプ | 仮名化後の形式 | 例 |
|-----------|---------------|-----|
| 患者ID / カルテ番号 | PATIENT_001 | P001 → PATIENT_001 |
| 氏名（漢字） | PERSON_001 | 山田太郎 → PERSON_001 |
| 氏名（カナ） | PERSON_KANA_001 | ヤマダタロウ → PERSON_KANA_001 |
| 電話番号 | PHONE_001 | 090-1234-5678 → PHONE_001 |
| メールアドレス | EMAIL_001 | test@example.com → EMAIL_001 |
| 住所 | ADDR_001 | 東京都新宿区... → ADDR_001 |
| 生年月日 | 1990年代（一般化）または BIRTHDATE_001 | 1990/01/15 → 1990年代 |
| 年齢 | 30代（一般化）または AGE_001 | 34歳 → 30代 |
| マイナンバー | MYNUMBER_001 | 123456789012 → MYNUMBER_001 |

---

## コマンド一覧

| コマンド | 説明 |
|----------|------|
| `workspace --add` | ファイルを仮名化してワークスペースに追加 |
| `workspace --add-all` | フォルダ内の全ファイルを一括追加 |
| `workspace --status` | ワークスペースの状態を表示 |
| `workspace --restore` | 結果ファイルを復元 |
| `workspace --restore-all` | output/内の全CSVを一括復元 |
| `wrap` | 仮名化環境内でコマンドを実行 |
| `chat` | ローカルLLM（Ollama）で対話 |
| `scan` | PII検出のみ（仮名化しない） |
| `pseudonymize` | 単発ファイルの仮名化 |
| `restore` | 単発ファイルの復元 |
| `scan-doc` | Word/PPTのPII検出 |
| `pseudonymize-doc` | Word/PPTの仮名化 |
| `restore-doc` | Word/PPTの復元 |
| `profile list` | 保存されたプロファイル一覧 |
| `profile show` | プロファイルの詳細表示 |
| `profile delete` | プロファイルを削除 |
| `profile export` | プロファイルをJSONにエクスポート |
| `profile import` | JSONからプロファイルをインポート |
| `profile create-default` | デフォルトプロファイルを作成 |

---

## 仮名化戦略

| 戦略 | 説明 | 使用例 |
|------|------|--------|
| `replace` | セマンティックトークンに置換（復元可能） | 氏名、患者ID、電話番号 |
| `generalize` | 一般化（年代、都道府県等） | 生年月日→年代、住所→都道府県 |
| `delete` | 列ごと削除 | 不要な個人情報列 |

---

## PII検出モード

DataAirlockは3つの検出モードをサポートしています。

| モード | 説明 | 特徴 |
|--------|------|------|
| `rule` | ルールベース（正規表現） | 高速、オフライン動作、デフォルト |
| `llm` | LLM（Ollama）のみ | 高精度、曖昧なPIIも検出 |
| `hybrid` | ルール + LLM の併用 | 最高精度、推奨 |

### CLIでの使用

```bash
# ルールベース（デフォルト）
dataairlock scan data.csv

# LLMモード
dataairlock scan data.csv -m llm

# ハイブリッドモード（推奨）
dataairlock scan data.csv -m hybrid

# 仮名化時も指定可能
dataairlock pseudonymize data.csv -m hybrid -p mypassword
```

### TUIでの使用

TUIでは、フォルダ処理時に「LLMを使用してPII検出の精度を向上させますか？」と確認が表示されます。
「はい」を選択すると、検出モードを選択できます。

### Ollamaのセットアップ

LLMモードを使用するにはOllamaが必要です：

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# サーバー起動
ollama serve

# モデルダウンロード
ollama pull llama3.1:8b
```

### ベンチマーク結果

内蔵テストデータ（11列、明確なPII 5列 + 曖昧なPII 2列 + 非PII 4列）での検出精度：

| モード | Precision | Recall | F1スコア | 処理時間 |
|--------|-----------|--------|----------|----------|
| `rule` | 1.000 | 0.714 | 0.833 | 0.002秒 |
| `llm` | 1.000 | 0.429 | 0.600 | 15.6秒 |
| `hybrid` | 1.000 | **0.857** | **0.923** | 10.1秒 |

**ハイブリッドモードはルールのみと比較してF1スコアが+10.8%向上**し、「担当者」列（「営業部 山本」など）の曖昧なPIIも検出できました。

---

## プロファイル機能

PII処理設定をプロファイルとして保存し、次回以降の作業で再利用できます。
定型業務（例: 毎月の患者データ処理）で同じ設定を繰り返し入力する手間を省けます。

### TUIでの使用

TUIでPIIを検出すると、プロファイルの使用を選択できます：

```
プロファイルを使用しますか？
  > 既存のプロファイルを使用
    新規に設定（プロファイル保存可）
    今回のみ設定（保存しない）
```

### CLIでの使用

```bash
# プロファイル一覧を表示
dataairlock profile list

# デフォルトプロファイルを作成
dataairlock profile create-default

# プロファイルの詳細を表示
dataairlock profile show 医療データ

# チームで共有（エクスポート/インポート）
dataairlock profile export 医療データ -o ./medical_profile.json
dataairlock profile import ./medical_profile.json
```

### プロファイル保存先

```
~/.config/dataairlock/profiles/
├── default.json
├── 医療データ.json
└── 人事データ.json
```

---

## ディレクトリ構成

```
my_project/
├── .airlock/                    # ワークスペース（Git管理OK）
│   ├── data/                    # 仮名化済みデータ
│   │   └── patients.csv         # PATIENT_001, PERSON_001...
│   ├── output/                  # LLMの出力先
│   ├── PROMPT.md                # LLM用プロンプトテンプレート
│   └── README.md
├── .airlock_mappings/           # マッピングファイル（Git管理NG）
│   └── patients.mapping.enc     # 暗号化されたマッピング
└── results/                     # 復元済み結果
    └── analysis.csv             # 山田太郎, 090-1234-5678...
```

---

## セキュリティ

- **暗号化マッピングファイル** — Fernet（AES-128-CBC）で暗号化
- **パスワード必須** — 復元にはパスワードが必要
- **ローカル処理** — 仮名化・復元はすべてローカルで実行。生データがクラウドに送信されることはありません。
- **Git除外** — `.airlock_mappings/` は `.gitignore` に自動追加

---

## 必要条件

- Python 3.10+
- Ollama（chatコマンドおよびLLM検出モードを使う場合のみ）

---

## 開発

```bash
# クローン
git clone https://github.com/akira0907/dataairlock.git
cd dataairlock

# 開発環境セットアップ
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# テスト実行
pytest
```

---

## ライセンス

AGPL-3.0

---

## 作者

[@akira0907](https://github.com/akira0907)
