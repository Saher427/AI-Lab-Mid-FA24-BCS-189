# run_evaluation.py
"""
Run all evaluation cases from data/final_eval.csv against the running gateway.
Usage: python run_evaluation.py
"""
import csv
import json
import time
import requests
import os
from datetime import datetime

API_URL = "http://127.0.0.1:8000/analyze"
EVAL_FILE = "data/final_eval.csv"
RESULTS_DIR = "results"

def run_eval():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    with open(EVAL_FILE, encoding="utf-8-") as f:
        rows = list(csv.DictReader(f))

    total = len(rows)
    passed = 0
    results = []

    print(f"\n{'='*70}")
    print(f"EVALUATION — {total} test cases")
    print(f"{'='*70}\n")

    for row in rows:
        prompt   = row["prompt"]
        expected = row["expected_policy"].upper()
        lang     = row.get("language", "en")

        try:
            resp = requests.post(API_URL, json={"prompt": prompt, "id": row["id"]}, timeout=10)
            data = resp.json()
            actual   = data.get("decision", "ERROR")
            latency  = data.get("latency_ms", 0)
            risk     = data.get("final_risk", 0)
            codes    = data.get("reason_codes", [])
        except Exception as e:
            actual  = "ERROR"
            latency = 0
            risk    = 0
            codes   = [str(e)]

        ok = (actual == expected)
        if ok:
            passed += 1

        result_row = {
            "id":         row["id"],
            "language":   lang,
            "attack_type": row.get("attack_type", ""),
            "expected":   expected,
            "actual":     actual,
            "pass":       ok,
            "final_risk": risk,
            "reason_codes": "|".join(codes),
            "latency_ms": latency,
        }
        results.append(result_row)

        status = "✅" if ok else "❌"
        print(f"{status} [{row['id']}] lang={lang} exp={expected} got={actual} risk={risk:.2f}")

    # Save CSV
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_csv = f"{RESULTS_DIR}/evaluation_{ts}.csv"
    latest  = f"{RESULTS_DIR}/latest_results.csv"

    fields = ["id","language","attack_type","expected","actual","pass","final_risk","reason_codes","latency_ms"]
    for path in [out_csv, latest]:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(results)

    accuracy = passed / total * 100
    latencies = [r["latency_ms"] for r in results if isinstance(r["latency_ms"], (int, float))]
    avg_lat = sum(latencies) / len(latencies) if latencies else 0

    summary = {
        "total": total, "passed": passed, "failed": total - passed,
        "accuracy": round(accuracy, 1), "avg_latency_ms": round(avg_lat, 1)
    }
    with open(f"{RESULTS_DIR}/metrics_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'='*70}")
    print(f"RESULTS: {passed}/{total} passed — Accuracy: {accuracy:.1f}%")
    print(f"Average latency: {avg_lat:.1f}ms")
    print(f"Results saved to: {latest}")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    run_eval()