#!/usr/bin/env python3
"""
Ollamaモデル比較スクリプト

異なるLLMモデルでのPII検出精度を比較します。

使用方法:
    python scripts/compare_models.py [--models model1,model2,model3]

前提条件:
    - Ollamaがインストール・起動済み
    - 比較するモデルがダウンロード済み
"""

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

# プロジェクトのsrcを追加
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dataairlock.llm_client import (
    LLMClient,
    is_ollama_running,
    get_available_models,
)
from dataairlock.hybrid_detector import (
    HybridPIIDetector,
    DetectionMode,
    check_ollama_status,
    OllamaSetupStatus,
)


# デフォルトで比較するモデル
DEFAULT_MODELS = [
    "llama3.1:8b",
    "gemma2:9b",
    "mistral:7b",
    "qwen2.5:7b",
]


def create_test_data() -> pd.DataFrame:
    """テスト用データセット"""
    return pd.DataFrame({
        # 日本語PII
        "患者氏名": ["山田太郎", "田中花子", "佐藤一郎"],
        "電話": ["090-1234-5678", "080-9876-5432", "03-1234-5678"],
        "メール": ["yamada@example.com", "tanaka@test.co.jp", "sato@mail.com"],
        "住所": ["東京都新宿区1-2-3", "大阪府大阪市北区4-5-6", "北海道札幌市中央区7-8-9"],
        "生年月日": ["1990/01/15", "1985/06/20", "1978/12/01"],

        # 曖昧なデータ
        "メモ": ["患者Aは通院中", "Bさんの処方箋確認", "担当者Cに連絡"],
        "コード": ["EMP001", "EMP002", "EMP003"],

        # 非PII
        "診察日": ["2024-01-15", "2024-01-16", "2024-01-17"],
        "診療科": ["内科", "外科", "皮膚科"],
    })


def create_ground_truth() -> dict[str, bool]:
    """正解データ（PIIかどうか）"""
    return {
        "患者氏名": True,
        "電話": True,
        "メール": True,
        "住所": True,
        "生年月日": True,
        "メモ": False,  # 曖昧だが直接PIIではない
        "コード": True,  # IDとして検出されるべき
        "診察日": False,
        "診療科": False,
    }


def benchmark_model(
    model_name: str,
    df: pd.DataFrame,
    ground_truth: dict[str, bool],
) -> dict:
    """指定モデルでPII検出を実行"""
    result = {
        "model": model_name,
        "available": False,
        "detections": {},
        "metrics": {},
        "time_sec": 0,
        "error": None,
    }

    # モデルが利用可能かチェック
    available_models = get_available_models()
    model_base = model_name.split(":")[0]

    if not any(model_base in m for m in available_models):
        result["error"] = f"モデル '{model_name}' が見つかりません"
        return result

    result["available"] = True

    try:
        # 検出実行
        start = time.time()
        detector = HybridPIIDetector(mode=DetectionMode.LLM_ONLY, llm_model=model_name)
        pii_results = detector.detect_pii_columns(df)
        elapsed = time.time() - start

        result["time_sec"] = round(elapsed, 3)

        # 検出結果を保存
        for col, det in pii_results.items():
            result["detections"][col] = {
                "type": det.pii_type.name,
                "confidence": det.confidence.value,
            }

        # 精度計算
        tp = fp = fn = tn = 0
        for col, is_pii in ground_truth.items():
            detected = col in result["detections"]
            if is_pii and detected:
                tp += 1
            elif is_pii and not detected:
                fn += 1
            elif not is_pii and detected:
                fp += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(ground_truth) if ground_truth else 0

        result["metrics"] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1, 3),
            "accuracy": round(accuracy, 3),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
        }

    except Exception as e:
        result["error"] = str(e)

    return result


def print_results(results: list[dict]):
    """結果を表示"""
    print("\n" + "=" * 80)
    print("Ollamaモデル比較結果")
    print("=" * 80)

    # 比較表
    print("\n### モデル別精度比較")
    print("-" * 80)
    print(f"{'モデル':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Accuracy':>10} {'時間(秒)':>10}")
    print("-" * 80)

    for r in results:
        if r["available"]:
            m = r["metrics"]
            print(f"{r['model']:<20} {m['precision']:>10.3f} {m['recall']:>10.3f} {m['f1_score']:>10.3f} {m['accuracy']:>10.3f} {r['time_sec']:>10.3f}")
        else:
            print(f"{r['model']:<20} {'N/A':>10} {'N/A':>10} {'N/A':>10} {'N/A':>10} {'N/A':>10}")
            if r["error"]:
                print(f"  エラー: {r['error']}")

    print("-" * 80)

    # 最良モデルを表示
    valid_results = [r for r in results if r["available"] and "f1_score" in r["metrics"]]
    if valid_results:
        best = max(valid_results, key=lambda x: x["metrics"]["f1_score"])
        print(f"\n最良モデル（F1スコア）: {best['model']} (F1={best['metrics']['f1_score']:.3f})")

        fastest = min(valid_results, key=lambda x: x["time_sec"])
        print(f"最速モデル: {fastest['model']} ({fastest['time_sec']:.3f}秒)")

    # 検出結果詳細
    print("\n### 検出結果詳細")
    for r in results:
        if r["available"]:
            print(f"\n[{r['model']}]")
            for col, det in sorted(r["detections"].items()):
                print(f"  {col}: {det['type']} ({det['confidence']})")
            if not r["detections"]:
                print("  (検出なし)")


def main():
    parser = argparse.ArgumentParser(description="Ollamaモデル比較")
    parser.add_argument(
        "--models",
        type=str,
        help=f"比較するモデル（カンマ区切り）。デフォルト: {','.join(DEFAULT_MODELS)}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="結果をJSONで出力",
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="利用可能なモデル一覧を表示して終了",
    )
    args = parser.parse_args()

    # Ollama状態チェック
    if not is_ollama_running():
        print("エラー: Ollamaが起動していません")
        print("  'ollama serve' でサーバーを起動してください")
        sys.exit(1)

    available = get_available_models()
    print(f"利用可能なモデル: {', '.join(available)}")

    if args.list_models:
        sys.exit(0)

    # モデルリスト
    if args.models:
        models = [m.strip() for m in args.models.split(",")]
    else:
        # デフォルトモデルから利用可能なものを選択
        models = []
        for model in DEFAULT_MODELS:
            model_base = model.split(":")[0]
            if any(model_base in m for m in available):
                models.append(model)

        if not models and available:
            # デフォルトモデルがない場合は利用可能なモデルから選択
            models = available[:3]

    if not models:
        print("エラー: 比較するモデルがありません")
        print(f"  'ollama pull {DEFAULT_MODELS[0]}' でモデルをダウンロードしてください")
        sys.exit(1)

    print(f"\n比較対象モデル: {', '.join(models)}")

    # テストデータ
    df = create_test_data()
    ground_truth = create_ground_truth()
    print(f"テストデータ: {len(df)}行 × {len(df.columns)}列")

    # ベンチマーク実行
    results = []
    for model in models:
        print(f"\n{model} を評価中...")
        result = benchmark_model(model, df, ground_truth)
        results.append(result)

    # 結果表示
    print_results(results)

    # JSON出力
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n結果をJSON出力: {args.output}")


if __name__ == "__main__":
    main()
