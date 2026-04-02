# app/policy_engine.py
from app.config import Config

class PolicyEngine:
    @staticmethod
    def decide(injection_score: float, pii_results, policy: str):
        """Decide action based on injection score, PII, and policy"""
        
        # Always block injection attempts
        if injection_score >= Config.INJECTION_THRESHOLD:
            return "Block", f"Injection detected (score: {injection_score:.2f})"
        
        # If PII detected, apply policy
        if pii_results and len(pii_results) > 0:
            if policy == "Mask":
                return "Mask", f"PII detected, masking {len(pii_results)} entities"
            elif policy == "Block":
                return "Block", f"PII detected and policy is Block"
            else:
                return "Allow", "PII detected but policy is Allow"
        
        # Everything safe
        return "Allow", "Safe prompt"