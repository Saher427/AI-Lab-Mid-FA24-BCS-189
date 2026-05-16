# app/pii/presidio_custom.py
import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import os
os.environ["SPACY_MODEL"] = "en_core_web_sm"

class CustomPresidio:
    def __init__(self):
        print("🔧 Initializing Presidio...")
        try:
            self.analyzer = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()
            self._add_recognizers()
            print("✅ Presidio ready")
        except Exception as e:
            print(f"⚠️ Presidio init error: {e}")
            self.analyzer = None
            self.anonymizer = None

    def _add_recognizers(self):
        try:
            # 1. Phone Number
            phone_recognizer = PatternRecognizer(
                supported_entity="PHONE_NUMBER",
                patterns=[
                    Pattern("phone_1", r"\b03[0-9]{2}[- ]?[0-9]{7}\b", 0.85),
                    Pattern("phone_2", r"\b\+92[0-9]{10}\b", 0.85),
                    Pattern("phone_3", r"\b0321[- ]?[0-9]{7}\b", 0.85),
                ],
                context=["phone", "mobile", "contact", "call", "number", "رابطہ"]
            )

            # 2. API Key
            api_recognizer = PatternRecognizer(
                supported_entity="API_KEY",
                patterns=[
                    Pattern("api_1", r"\bsk-[a-zA-Z0-9]{40,64}\b", 0.95),
                    Pattern("api_2", r"\bpk-[a-zA-Z0-9]{40,64}\b", 0.95),
                    Pattern("api_3", r"\bsk-proj-[a-zA-Z0-9]{32,64}\b", 0.90),
                ],
                context=["api", "key", "secret", "token", "openai"]
            )

            # 3. Internal / Student ID
            id_recognizer = PatternRecognizer(
                supported_entity="STUDENT_ID",
                patterns=[
                    Pattern("id_1", r"\bSTU-[0-9]{6}\b", 0.85),
                    Pattern("id_2", r"\bFA[0-9]{2}-BCS-[0-9]{3}\b", 0.90),
                    Pattern("id_3", r"\bEMP-[0-9]{4}\b", 0.80),
                    Pattern("id_4", r"\bHOG-[0-9]{6}\b", 0.80),
                ],
                context=["student", "id", "registration", "employee", "rollno"]
            )

            # 4. Email
            email_recognizer = PatternRecognizer(
                supported_entity="EMAIL_ADDRESS",
                patterns=[
                    Pattern("email", r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", 0.97),
                ],
                context=["email", "mail", "address", "ای میل"]
            )

            # 5. CNIC (Pakistani national ID) — NEW custom recognizer
            cnic_recognizer = PatternRecognizer(
                supported_entity="CNIC",
                patterns=[
                    Pattern("cnic_1", r"\b[0-9]{5}-[0-9]{7}-[0-9]\b", 0.95),
                    Pattern("cnic_2", r"\b[0-9]{13}\b", 0.70),
                ],
                context=["cnic", "national id", "identity card", "شناختی کارڈ", "id card"]
            )

            if self.analyzer:
                self.analyzer.registry.add_recognizer(phone_recognizer)
                self.analyzer.registry.add_recognizer(api_recognizer)
                self.analyzer.registry.add_recognizer(id_recognizer)
                self.analyzer.registry.add_recognizer(email_recognizer)
                self.analyzer.registry.add_recognizer(cnic_recognizer)
                print("✅ Custom recognizers added: PHONE, API_KEY, STUDENT_ID, EMAIL, CNIC")
        except Exception as e:
            print(f"⚠️ Recognizer error: {e}")

    def analyze(self, text: str):
        if not self.analyzer:
            return self._regex_fallback(text)
        try:
            results = self.analyzer.analyze(text=text, language="en")
            # Run regex fallback and merge
            regex_results = self._regex_fallback(text)
            merged = list(results)
            for r in regex_results:
                if not any(abs(r.start - x.start) < 3 for x in merged):
                    merged.append(r)
            if merged:
                print(f"🔍 PII found: {[(r.entity_type, text[r.start:r.end]) for r in merged]}")
            return merged
        except Exception as e:
            print(f"⚠️ Presidio analyze error: {e}")
            return self._regex_fallback(text)

    def _regex_fallback(self, text: str):
        from presidio_analyzer import RecognizerResult
        results = []
        # CNIC
        for m in re.finditer(r"\b[0-9]{5}-[0-9]{7}-[0-9]\b", text):
            results.append(RecognizerResult("CNIC", m.start(), m.end(), 0.95))
        # Email
        for m in re.finditer(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text):
            results.append(RecognizerResult("EMAIL_ADDRESS", m.start(), m.end(), 0.97))
        # Phone
        for m in re.finditer(r"\b(03[0-9]{2}[- ]?[0-9]{7}|\+92[0-9]{10})\b", text):
            results.append(RecognizerResult("PHONE_NUMBER", m.start(), m.end(), 0.85))
        # Student ID
        for m in re.finditer(r"\b(FA[0-9]{2}-BCS-[0-9]{3}|STU-[0-9]{6}|EMP-[0-9]{4})\b", text):
            results.append(RecognizerResult("STUDENT_ID", m.start(), m.end(), 0.90))
        # API Key
        for m in re.finditer(r"\bsk-[a-zA-Z0-9]{40,64}\b", text):
            results.append(RecognizerResult("API_KEY", m.start(), m.end(), 0.95))
        # Credit Card
        for m in re.finditer(r"\b[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}[- ][0-9]{4}\b", text):
            results.append(RecognizerResult("CREDIT_CARD", m.start(), m.end(), 0.90))
        return results

    def anonymize(self, text: str, results):
        if not results:
            return _wrap(text)
        if self.anonymizer:
            try:
                operators = {
                    "PHONE_NUMBER":  OperatorConfig("replace", {"new_value": "<PHONE>"}),
                    "API_KEY":       OperatorConfig("replace", {"new_value": "<API_KEY>"}),
                    "STUDENT_ID":    OperatorConfig("replace", {"new_value": "<STUDENT_ID>"}),
                    "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
                    "CNIC":          OperatorConfig("replace", {"new_value": "<CNIC>"}),
                    "PERSON":        OperatorConfig("replace", {"new_value": "<PERSON>"}),
                    "CREDIT_CARD":   OperatorConfig("replace", {"new_value": "<CREDIT_CARD>"}),
                }
                return self.anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
            except Exception as e:
                print(f"⚠️ Presidio anonymize error: {e}")
        # Fallback: star out
        sorted_r = sorted(results, key=lambda x: x.start, reverse=True)
        t = text
        for r in sorted_r:
            t = t[:r.start] + "*" * (r.end - r.start) + t[r.end:]
        return _wrap(t)

def _wrap(text):
    class R:
        def __init__(self, t): self.text = t
    return R(text)