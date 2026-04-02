# tests/run_eval.py
import requests
import time
import csv
import os
import sys
from test_cases import TEST_CASES

URL = "http://127.0.0.1:8000/secure-llm"

print("🚀 Starting evaluation...\n")

# Create eval_results folder if it doesn't exist
os.makedirs("../eval_results", exist_ok=True)

# Check if server is running
try:
    requests.get("http://127.0.0.1:8000/health", timeout=2)
    print("✅ Server is running!\n")
except:
    print("❌ ERROR: Server is not running!")
    print("Start server first: uvicorn app.main:app --reload")
    sys.exit(1)

results = []
passed = 0
failed = 0

for case in TEST_CASES:
    try:
        start = time.perf_counter()
        response = requests.post(URL, json={"prompt": case["prompt"]}, timeout=10)
        latency = (time.perf_counter() - start) * 1000
        
        if response.status_code == 200:
            data = response.json()
            action = data.get("status", "unknown")
            
            action_map = {"allowed": "Allow", "blocked": "Block", "masked": "Mask"}
            mapped_action = action_map.get(action, action)
            
            if mapped_action == case["expected"]:
                passed += 1
                result = "✅"
            else:
                failed += 1
                result = "❌"
            
            print(f"{result} Test {case['id']:2d}: {case['name']:35s} → {mapped_action:6s} ({latency:5.1f}ms) | Expected: {case['expected']}")
            
            # Store result for CSV
            results.append({
                "ID": case["id"],
                "Scenario": case["name"],
                "Prompt": case["prompt"][:100],
                "Action": mapped_action,
                "Expected": case["expected"],
                "Latency_ms": round(latency, 2),
                "Pass": "Yes" if mapped_action == case["expected"] else "No"
            })
        else:
            failed += 1
            print(f"❌ Test {case['id']:2d}: HTTP {response.status_code}")
            
    except Exception as e:
        failed += 1
        print(f"❌ Test {case['id']:2d}: ERROR - {e}")

print("\n" + "="*60)
print(f"📊 EVALUATION SUMMARY")
print("="*60)
print(f"Total Tests:        {len(TEST_CASES)}")
print(f"✅ Passed:           {passed}")
print(f"❌ Failed:           {failed}")
print(f"📈 Accuracy:         {(passed/len(TEST_CASES))*100:.1f}%")
print("="*60)

# Save results to CSV
if results:
    csv_path = "../eval_results/evaluation_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\n📁 Results saved to: {csv_path}")
else:
    print("\n⚠️ No results to save")