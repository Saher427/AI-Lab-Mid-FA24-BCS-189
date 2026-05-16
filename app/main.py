# app/main.py
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from config_loader import Config
from app.detectors.rule_detector import RuleDetector
from app.detectors.semantic_detector import SemanticDetector
from app.pii.presidio_custom import CustomPresidio
from app.policy.policy_engine import PolicyEngine
from app.utils.language import detect_language
from app.utils.logging import log_request

app = FastAPI(title="LLM Security Gateway — Final")

# Allow browser requests from the same origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

print("🚀 Starting LLM Security Gateway (Final)...")

Config.load()
rule_det     = RuleDetector()
semantic_det = SemanticDetector()
presidio     = CustomPresidio()

# ── Serve the frontend ──────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def frontend():
    """Serve the web UI."""
    html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h2>Frontend not found. Place index.html in the static/ folder.</h2>", status_code=404)

# ── API endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "config": {
            "rule_threshold":     Config.RULE_THRESHOLD,
            "semantic_threshold": Config.SEMANTIC_THRESHOLD,
            "block_threshold":    Config.BLOCK_THRESHOLD,
            "policy":             Config.POLICY,
        }
    }

@app.post("/analyze")
async def analyze(request: Request):
    t0 = time.perf_counter()

    try:
        data     = await request.json()
        prompt   = data.get("prompt", "")
        input_id = data.get("id", "unknown")

        if not prompt:
            raise HTTPException(status_code=400, detail="Missing 'prompt' field")

        # 1. Language detection
        language = detect_language(prompt)

        # 2. Rule-based score
        rule_score = rule_det.score(prompt)

        # 3. Semantic score
        semantic_score = semantic_det.score(prompt)

        # 4. PII detection
        pii_results  = presidio.analyze(prompt)
        pii_entities = [
            {"type": r.entity_type, "text": prompt[r.start:r.end], "score": round(r.score, 2)}
            for r in pii_results
        ]

        # 5. Policy decision
        decision, final_risk, reason_codes = PolicyEngine.decide(
            rule_score, semantic_score, pii_results, Config
        )

        # 6. Build safe_text
        safe_text = None
        if decision == "MASK":
            anonymized = presidio.anonymize(prompt, pii_results)
            safe_text  = anonymized.text
        elif decision == "ALLOW":
            safe_text = prompt

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        response = {
            "input_id":       input_id,
            "language":       language,
            "rule_score":     round(rule_score, 3),
            "semantic_score": round(semantic_score, 3),
            "final_risk":     round(final_risk, 3),
            "pii_entities":   pii_entities,
            "decision":       decision,
            "safe_text":      safe_text,
            "reason_codes":   reason_codes,
            "latency_ms":     latency_ms,
        }

        # 7. Audit log
        log_request({
            "input_id":       input_id,
            "language":       language,
            "rule_score":     round(rule_score, 3),
            "semantic_score": round(semantic_score, 3),
            "final_risk":     round(final_risk, 3),
            "pii_count":      len(pii_results),
            "decision":       decision,
            "reason_codes":   reason_codes,
            "latency_ms":     latency_ms,
        })

        print(f"📊 [{decision}] lang={language} rule={rule_score:.2f} sem={semantic_score:.2f} pii={len(pii_results)} {latency_ms}ms")
        return response

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))