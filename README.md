\# LLM Security Gateway — Lab Final

\*\*FA24-BCS-189 | Saher Irfan | CSC 262\*\*



\## Overview

Robust pre-model security gateway with hybrid detection (rule-based + TF-IDF ML),

multilingual support (English, Urdu, Korean), Presidio PII anonymization, and

auditable policy decisions.



\## Installation



```bash

git clone <your-repo-url>

cd llm-security-gateway

python -m venv venv

\# Windows:

venv\\Scripts\\activate

\# macOS/Linux:

source venv/bin/activate



pip install -r requirements.txt

python -m spacy download en\_core\_web\_sm

```



\## Running the Gateway

```bash

python -m uvicorn app.main:app --reload

```

Server runs at: http://127.0.0.1:8000



\## Example Request

```bash

curl -X POST http://127.0.0.1:8000/analyze \\

&#x20; -H "Content-Type: application/json" \\

&#x20; -d '{"prompt": "What is machine learning?", "id": "test\_001"}'

```



\## Running Evaluation

Open a second terminal:

```bash

python run\_evaluation.py

```

Results saved in `results/` folder.



\## API Endpoints

| Method | Endpoint   | Description           |

|--------|------------|-----------------------|

| GET    | /          | Status check          |

| GET    | /health    | Config and health     |

| POST   | /analyze   | Analyze a prompt      |

