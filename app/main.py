# app/main.py
import time
import traceback
import re
from fastapi import FastAPI, Request, HTTPException

from app.injection_detector import InjectionDetector
from app.presidio_handler import CustomPresidio
from app.policy_engine import PolicyEngine
from app.config import Config

# Initialize FastAPI
app = FastAPI(title="LLM Security Gateway")

print("🚀 Starting LLM Security Gateway...")

# Initialize components
Config.load()
detector = InjectionDetector()
presidio = CustomPresidio()

@app.get("/")
async def root():
    return {
        "message": "LLM Security Gateway is running",
        "status": "active",
        "config": {
            "injection_threshold": Config.INJECTION_THRESHOLD,
            "policy": Config.POLICY
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "config": {
            "threshold": Config.INJECTION_THRESHOLD,
            "policy": Config.POLICY
        }
    }

def detect_pii(text: str):
    """Direct PII detection using regex - FIXED for false positives"""
    from presidio_analyzer import RecognizerResult
    results = []
    
    print(f"🔍 Running PII detection on: {text[:80]}...")
    
    # ============================================
    # PHONE NUMBERS - Must have 10+ digits and proper format
    # ============================================
    phone_patterns = [
        (r"\b03[0-9]{2}[- ]?[0-9]{7}\b", "standard"),   # 0300-1234567
        (r"\b03[0-9]{9}\b", "standard"),                 # 03001234567
        (r"\b\+92[0-9]{10}\b", "international"),         # +923001234567
        (r"\b0321[- ]?[0-9]{7}\b", "standard"),          # 0321-1234567
    ]
    
    for pattern, _ in phone_patterns:
        for match in re.finditer(pattern, text):
            detected = match.group()
            # Count digits in the detected string
            digit_count = sum(c.isdigit() for c in detected)
            # Only detect if it has 9-13 digits (real phone number)
            if 9 <= digit_count <= 13:
                # Additional check: must start with 03 or +92
                if detected.startswith('03') or detected.startswith('+92'):
                    results.append(RecognizerResult(
                        entity_type="PHONE_NUMBER",
                        start=match.start(),
                        end=match.end(),
                        score=0.85
                    ))
                    print(f"  ✅ Found PHONE: {detected}")
    
    # ============================================
    # EMAILS - Must have @ symbol and domain
    # ============================================
    email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    for match in re.finditer(email_pattern, text):
        results.append(RecognizerResult(
            entity_type="EMAIL",
            start=match.start(),
            end=match.end(),
            score=0.95
        ))
        print(f"  ✅ Found EMAIL: {match.group()}")
    
    # ============================================
    # API KEYS - Must have prefix and be long
    # ============================================
    api_patterns = [
        r"\bsk-[a-zA-Z0-9]{40,48}\b",
        r"\bpk-[a-zA-Z0-9]{40,48}\b",
        r"\bsk-proj-[a-zA-Z0-9]{40,64}\b",
    ]
    for pattern in api_patterns:
        for match in re.finditer(pattern, text):
            detected = match.group()
            if len(detected) >= 40:  # API keys are long
                results.append(RecognizerResult(
                    entity_type="API_KEY",
                    start=match.start(),
                    end=match.end(),
                    score=0.85
                ))
                print(f"  ✅ Found API_KEY: {detected[:30]}...")
    
    # ============================================
    # INTERNAL IDs - Must have prefix and proper format
    # ============================================
    id_patterns = [
        (r"\bSTU-[0-9]{6}\b", "STU"),
        (r"\bHOG-[0-9]{6}\b", "HOG"),
        (r"\bEMP-[0-9]{4}\b", "EMP"),
    ]
    for pattern, prefix in id_patterns:
        for match in re.finditer(pattern, text):
            detected = match.group()
            # Verify it matches the expected format
            if detected.startswith(prefix):
                results.append(RecognizerResult(
                    entity_type="INTERNAL_ID",
                    start=match.start(),
                    end=match.end(),
                    score=0.80
                ))
                print(f"  ✅ Found ID: {detected}")
    
    # ============================================
    # CREDIT CARDS - Added for Test 20
    # ============================================
    credit_card_patterns = [
        r"\b[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}[- ][0-9]{4}\b",  # 1234-5678-9012-3456
        r"\b[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}[- ][0-9]{4}\b",  # 4111-1111-1111-1111
    ]
    for pattern in credit_card_patterns:
        for match in re.finditer(pattern, text):
            results.append(RecognizerResult(
                entity_type="CREDIT_CARD",
                start=match.start(),
                end=match.end(),
                score=0.90
            ))
            print(f"  ✅ Found CREDIT_CARD: {match.group()}")
    
    print(f"  📊 Total PII found: {len(results)}")
    return results

def anonymize_text(text: str, results):
    """Simple anonymization"""
    if not results:
        return text
    
    # Sort by start position in reverse to not mess up indices
    sorted_results = sorted(results, key=lambda x: x.start, reverse=True)
    new_text = text
    for r in sorted_results:
        replacement = "*" * (r.end - r.start)
        new_text = new_text[:r.start] + replacement + new_text[r.end:]
    return new_text

@app.post("/secure-llm")
async def secure_llm(request: Request):
    start_total = time.perf_counter()
    
    try:
        data = await request.json()
        user_input = data.get("prompt", "")
        
        if not user_input:
            raise HTTPException(status_code=400, detail="Missing 'prompt' field")
        
        # 1. Injection Detection
        inj_start = time.perf_counter()
        injection_score, inj_verdict = detector.calculate_score(user_input)
        inj_latency = (time.perf_counter() - inj_start) * 1000
        
        # 2. PII Detection - Try Presidio first, fallback to regex
        pres_start = time.perf_counter()
        try:
            pii_results = presidio.analyze(user_input)
            if not pii_results:
                pii_results = detect_pii(user_input)
        except Exception as e:
            print(f"⚠️ Presidio failed, using regex fallback: {e}")
            pii_results = detect_pii(user_input)
        pres_latency = (time.perf_counter() - pres_start) * 1000
        
        # 3. Policy Decision
        policy_start = time.perf_counter()
        
        if injection_score >= Config.INJECTION_THRESHOLD:
            action = "Block"
            reason = f"Injection detected (score: {injection_score:.2f})"
        elif pii_results and len(pii_results) > 0:
            if Config.POLICY == "Mask":
                action = "Mask"
                reason = f"PII detected: {len(pii_results)} entities found"
            elif Config.POLICY == "Block":
                action = "Block"
                reason = "PII detected and policy is Block"
            else:
                action = "Allow"
                reason = f"PII detected but policy is {Config.POLICY}"
        else:
            action = "Allow"
            reason = "Safe prompt"
        
        policy_latency = (time.perf_counter() - policy_start) * 1000
        total_latency = (time.perf_counter() - start_total) * 1000
        
        # Build response
        if action == "Block":
            output = {
                "status": "blocked",
                "reason": reason,
                "injection_score": round(injection_score, 2),
                "pii_detected": len(pii_results) if pii_results else 0,
                "latency_ms": round(total_latency, 2)
            }
        elif action == "Mask":
            try:
                anonymized = presidio.anonymize(user_input, pii_results)
                processed = anonymized.text
            except:
                processed = anonymize_text(user_input, pii_results)
            
            output = {
                "status": "masked",
                "original_prompt": user_input,
                "processed_prompt": processed,
                "reason": reason,
                "injection_score": round(injection_score, 2),
                "pii_detected": len(pii_results) if pii_results else 0,
                "latency_ms": round(total_latency, 2)
            }
        else:
            output = {
                "status": "allowed",
                "processed_prompt": user_input,
                "reason": reason,
                "injection_score": round(injection_score, 2),
                "pii_detected": len(pii_results) if pii_results else 0,
                "latency_ms": round(total_latency, 2)
            }
        
        print(f"📊 Decision: {action} | Score: {injection_score:.2f} | PII: {len(pii_results) if pii_results else 0} | Latency: {total_latency:.2f}ms")
        
        return output
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error: {e}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")