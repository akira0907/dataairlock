---
title: '【5分で完了】機密データをClaude Codeで安全に分析する方法'
tags:
  - Python
  - セキュリティ
  - 個人情報保護
  - LLM
  - Claude
private: false
updated_at: ''
id: null
organization_url_name: null
slide: false
ignorePublish: false
---

## こんな経験ありませんか？

「顧客データをClaudeに分析させたいけど、個人情報をクラウドに送るのは怖い...」

Claude CodeやChatGPTは強力ですが、機密データをそのまま渡すのは抵抗がありますよね。

この記事では、**ローカルでデータを仮名化してからLLMに渡す方法**を紹介します。

## 解決策: DataAirlock

[DataAirlock](https://github.com/akira0907/dataairlock)は、個人情報を**ローカルで仮名化**し、分析結果を**ワンコマンドで復元**できるCLIツールです。

```
機密データ → [仮名化] → Claude Code → [復元] → 実名入り結果
           ↑ローカル処理          ↑ローカル処理
```

## インストール

```bash
pip install dataairlock
```

これだけです。Python 3.10以上が必要です。

## 実践: 顧客データを仮名化してClaudeで分析

### Step 1: サンプルデータを用意

```csv:customers.csv
顧客ID,氏名,電話番号,メール,購入金額
C001,山田太郎,090-1234-5678,yamada@example.com,15000
C002,佐藤花子,080-9876-5432,sato@example.com,32000
C003,鈴木一郎,070-1111-2222,suzuki@example.com,8500
```

### Step 2: ワークスペースを作成（仮名化）

```bash
dataairlock workspace ./analysis --add customers.csv -p mypassword
```

出力:
```
✓ ワークスペースを作成しました: ./analysis/.airlock
✓ 仮名化完了: customers.csv
  - 氏名 → PERSON_001, PERSON_002, ...
  - 電話番号 → PHONE_001, PHONE_002, ...
  - メール → EMAIL_001, EMAIL_002, ...
```

仮名化されたデータ（`./analysis/.airlock/data/customers.csv`）:

```csv
顧客ID,氏名,電話番号,メール,購入金額
C001,PERSON_001,PHONE_001,EMAIL_001,15000
C002,PERSON_002,PHONE_002,EMAIL_002,32000
C003,PERSON_003,PHONE_003,EMAIL_003,8500
```

**ポイント**: 数値（購入金額）はそのまま残るので、LLMが分析できます。

### Step 3: Claude Codeで分析

```bash
cd ./analysis/.airlock
claude
```

Claude Codeに仮名化データを分析させます:

```
> customers.csvを分析して、購入金額の傾向をまとめてください
```

Claudeの出力例:
```
## 分析結果

- PERSON_002が最も購入金額が高い（32,000円）
- 平均購入金額: 18,500円
- PERSON_003は平均以下のため、リテンション施策を検討
```

### Step 4: 結果を復元

分析結果をファイルに保存して復元します:

```bash
# .airlock/output/ に結果を保存後
dataairlock workspace ./analysis --restore-all -p mypassword
```

復元された結果（`./analysis/results/`）:
```
## 分析結果

- 佐藤花子が最も購入金額が高い（32,000円）
- 平均購入金額: 18,500円
- 鈴木一郎は平均以下のため、リテンション施策を検討
```

**PERSON_002 → 佐藤花子** のように自動で復元されます。

## もっと精度を上げたい場合

正規表現だけでは検出しにくいPII（例:「営業部 山本」のような曖昧な表現）も検出したい場合は、**ハイブリッドモード**が使えます。

```bash
# Ollamaをインストール
brew install ollama
ollama serve &
ollama pull llama3.1:8b

# ハイブリッドモードで仮名化
pip install dataairlock[ollama]
dataairlock scan customers.csv -m hybrid
```

ベンチマーク結果では、ハイブリッドモードは**F1スコアが+10.8%向上**しました。

## 対応フォーマット

| 形式 | 対応 |
|------|------|
| CSV | ✅ |
| Excel (.xlsx) | ✅ |
| Word (.docx) | ✅ |
| PowerPoint (.pptx) | ✅ |

## まとめ

1. `pip install dataairlock`
2. `dataairlock workspace ./project --add data.csv -p password`
3. Claude Codeで分析
4. `dataairlock workspace ./project --restore-all -p password`

これで機密データを安全にLLMで分析できます。

## リンク

- GitHub: https://github.com/akira0907/dataairlock
- PyPI: https://pypi.org/project/dataairlock/
- 詳細な解説（Zenn）: https://zenn.dev/akira0907/articles/dataairlock-hybrid-pii-detection

質問やフィードバックはGitHub Issuesへお願いします！
