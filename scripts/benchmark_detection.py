#!/usr/bin/env python3
"""
PII検出モードのベンチマーク比較スクリプト

ルールベース、LLM、ハイブリッドの検出精度と速度を比較します。

使用方法:
    python scripts/benchmark_detection.py [--data-file PATH]
"""

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

# プロジェクトのsrcを追加
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dataairlock.pseudonymizer import detect_pii_columns, PIIType
from dataairlock.hybrid_detector import (
    HybridPIIDetector,
    DetectionMode,
    detect_pii_hybrid,
    check_ollama_status,
    OllamaSetupStatus,
)


def create_test_data() -> pd.DataFrame:
    """テスト用データセットを作成"""
    return pd.DataFrame({
        # 明確なPII（ルールで検出可能）
        "氏名": ["山田太郎", "田中花子", "佐藤一郎", "鈴木二郎", "高橋三郎"],
        "電話番号": ["090-1234-5678", "080-9876-5432", "03-1234-5678", "06-9876-5432", "070-1111-2222"],
        "メールアドレス": ["yamada@example.com", "tanaka@test.co.jp", "sato@mail.com", "suzuki@example.org", "takahashi@test.net"],
        "住所": ["東京都新宿区1-2-3", "大阪府大阪市北区4-5-6", "北海道札幌市中央区7-8-9", "福岡県福岡市博多区10-11-12", "愛知県名古屋市中区13-14-15"],
        "生年月日": ["1990/01/15", "1985/06/20", "1978/12/01", "2000/03/10", "1995/09/25"],

        # 曖昧なPII（LLMで検出効果的）
        "担当者": ["営業部 山本", "開発部 木村", "人事部 小林", "総務部 加藤", "経理部 吉田"],
        "コメント": ["患者Aは快方に向かっている", "クライアントBとの会議設定", "顧客Cからのクレーム対応", "取引先Dへの納品完了", "協力会社Eとの契約更新"],
        "ID番号": ["EMP001", "EMP002", "EMP003", "EMP004", "EMP005"],

        # 非PII
        "商品名": ["りんご", "みかん", "バナナ", "ぶどう", "いちご"],
        "価格": [100, 200, 150, 300, 250],
        "カテゴリ": ["果物", "果物", "果物", "果物", "果物"],
    })


def create_ground_truth() -> dict[str, str]:
    """正解データ（各列のPIIタイプ）"""
    return {
        "氏名": "NAME",
        "電話番号": "PHONE",
        "メールアドレス": "EMAIL",
        "住所": "ADDRESS",
        "生年月日": "BIRTHDATE",
        "担当者": "NAME",  # 人名を含む
        "コメント": None,  # PIIではない（または曖昧）
        "ID番号": "PATIENT_ID",  # IDパターン
        "商品名": None,
        "価格": None,
        "カテゴリ": None,
    }


def benchmark_mode(
    df: pd.DataFrame,
    mode: DetectionMode,
    ground_truth: dict[str, str],
    iterations: int = 3,
) -> dict:
    """指定モードでベンチマークを実行"""
    results = {
        "mode": mode.value,
        "times": [],
        "detections": {},
        "metrics": {},
    }

    for i in range(iterations):
        start = time.time()

        if mode == DetectionMode.RULE_ONLY:
            pii_columns = detect_pii_columns(df)
        else:
            pii_columns = detect_pii_hybrid(df, mode=mode)

        elapsed = time.time() - start
        results["times"].append(elapsed)

        # 最後のイテレーションの結果を保存
        if i == iterations - 1:
            for col, result in pii_columns.items():
                results["detections"][col] = {
                    "type": result.pii_type.name,
                    "confidence": result.confidence.value,
                    "matched_by": result.matched_by,
                }

    # 精度計算
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    for col, expected_type in ground_truth.items():
        detected = col in results["detections"]
        is_pii = expected_type is not None

        if is_pii and detected:
            true_positives += 1
        elif is_pii and not detected:
            false_negatives += 1
        elif not is_pii and detected:
            false_positives += 1

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    results["metrics"] = {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "avg_time_sec": round(sum(results["times"]) / len(results["times"]), 3),
        "min_time_sec": round(min(results["times"]), 3),
        "max_time_sec": round(max(results["times"]), 3),
    }

    return results


def print_results(results: list[dict]):
    """結果を表示"""
    print("\n" + "=" * 70)
    print("PII検出ベンチマーク結果")
    print("=" * 70)

    # 比較表
    print("\n### 精度比較")
    print("-" * 60)
    print(f"{'モード':<15} {'Precision':>10} {'Recall':>10} {'F1':>10} {'時間(秒)':>12}")
    print("-" * 60)

    for r in results:
        m = r["metrics"]
        print(f"{r['mode']:<15} {m['precision']:>10.3f} {m['recall']:>10.3f} {m['f1_score']:>10.3f} {m['avg_time_sec']:>12.3f}")

    print("-" * 60)

    # 検出結果詳細
    print("\n### 検出結果詳細")
    for r in results:
        print(f"\n[{r['mode']}]")
        for col, det in sorted(r["detections"].items()):
            print(f"  {col}: {det['type']} ({det['confidence']}, {det['matched_by']})")


def main():
    parser = argparse.ArgumentParser(description="PII検出ベンチマーク")
    parser.add_argument(
        "--data-file",
        type=Path,
        help="テストデータファイル（CSV）。未指定時は内蔵テストデータを使用",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="各モードのイテレーション回数（デフォルト: 3）",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="結果をJSONで出力",
    )
    args = parser.parse_args()

    # データ準備
    if args.data_file:
        if not args.data_file.exists():
            print(f"エラー: ファイルが見つかりません: {args.data_file}")
            sys.exit(1)
        df = pd.read_csv(args.data_file)
        ground_truth = {}  # カスタムデータの場合は正解なし
        print(f"データファイル: {args.data_file}")
    else:
        df = create_test_data()
        ground_truth = create_ground_truth()
        print("内蔵テストデータを使用")

    print(f"データサイズ: {len(df)}行 × {len(df.columns)}列")

    # Ollama状態チェック
    ollama_status = check_ollama_status()
    print(f"Ollama状態: {ollama_status.value}")

    # ベンチマーク実行
    results = []

    # ルールベース（常に実行可能）
    print("\nルールベース検出を実行中...")
    results.append(benchmark_mode(df, DetectionMode.RULE_ONLY, ground_truth, args.iterations))

    # LLM/ハイブリッド（Ollamaが使える場合のみ）
    if ollama_status == OllamaSetupStatus.READY:
        print("LLM検出を実行中...")
        results.append(benchmark_mode(df, DetectionMode.LLM_ONLY, ground_truth, args.iterations))

        print("ハイブリッド検出を実行中...")
        results.append(benchmark_mode(df, DetectionMode.HYBRID, ground_truth, args.iterations))
    else:
        print(f"\n⚠️  Ollamaが利用できないため、LLM/ハイブリッドモードはスキップ")
        print(f"   状態: {ollama_status.value}")

    # 結果表示
    print_results(results)

    # JSON出力
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n結果をJSON出力: {args.output}")


if __name__ == "__main__":
    main()
