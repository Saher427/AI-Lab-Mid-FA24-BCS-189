# LLM Security Gateway

A pre-model security gateway that inspects prompts before they reach an LLM — detecting prompt-injection attempts, scoring risk with a hybrid rule-based + machine learning approach, identifying and anonymizing PII, and returning an auditable policy decision (allow, mask, or block).

## What it does

Every incoming prompt is analyzed through several layers before a decision is made:

1. **Language detection** — supports English, Urdu, and Korean
2. **Rule-based scoring** — pattern/heuristic checks for known attack signatures
3. **Semantic scoring** — a TF-IDF-based ML model that scores prompts for injection-style intent, catching attacks that don't match a fixed rule
4. **PII detection & anonymization** — powered by Microsoft Presidio, flags and can redact sensitive entities (names, emails, etc.)
5. **Policy engine** — combines all signals into a final risk score and decision (`ALLOW`, `MASK`, or `BLOCK`), with reason codes explaining why

Every request is logged for auditability, and each response includes latency, which matters when a security layer sits in front of a live model.

## Tech stack

- **FastAPI** — API layer
- **Presidio** (analyzer + anonymizer) — PII detection/redaction
- **spaCy** — NLP backbone for Presidio
- **scikit-learn** — semantic/ML risk scoring
- **langdetect** — multilingual prompt detection

## Project structure

```
├── app/
│   ├── detectors/       # rule-based & semantic (ML) detectors
│   ├── pii/             # Presidio-based PII analysis & anonymization
│   ├── policy/          # decision engine combining all signals
│   ├── utils/           # language detection, audit logging
│   └── main.py          # FastAPI app & endpoints
├── config/               # gateway configuration
├── data/                 # evaluation dataset
├── static/               # frontend (served at "/")
├── tests/                # test suite
├── results/               # evaluation output (latest run + summary)
├── config_loader.py
├── requirements.txt
└── run_evaluation.py
```

## Setup

```bash
git clone <your-repo-url>
cd llm-security-gateway

python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

## Running the gateway

```bash
python -m uvicorn app.main:app --reload
```

Server runs at `http://127.0.0.1:8000`. A basic web UI is served at `/`.

### Example request

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is machine learning?", "id": "test_001"}'
```

Example response shape:
```json
{
  "input_id": "test_001",
  "language": "en",
  "rule_score": 0.02,
  "semantic_score": 0.05,
  "final_risk": 0.04,
  "pii_entities": [],
  "decision": "ALLOW",
  "safe_text": "What is machine learning?",
  "reason_codes": [],
  "latency_ms": 12.4
}
```

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serves the web UI |
| GET | `/health` | Health check + current config (thresholds, policy) |
| POST | `/analyze` | Analyze a prompt and return a policy decision |

## Running the evaluation suite

With the server running in one terminal, run the evaluation in another:

```bash
python run_evaluation.py
```

This sends every test case in `data/final_eval.csv` (covering multiple languages and attack types) through the live gateway, compares the actual decision to the expected one, and writes:

- `results/latest_results.csv` — per-case pass/fail breakdown
- `results/metrics_summary.json` — overall accuracy and average latency

## Notes

This was built as a final project for an Artificial Intelligence course. It's a working prototype demonstrating a layered detection approach (rules + ML + PII-aware policy) rather than a production-hardened gateway — thresholds and the semantic model would need further tuning and adversarial testing before real-world deployment.