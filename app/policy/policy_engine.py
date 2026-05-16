# app/policy/policy_engine.py
from config_loader import Config

class PolicyEngine:
    @staticmethod
    def decide(rule_score: float, semantic_score: float, pii_results: list, cfg: Config):
        """
        Combine rule_score, semantic_score, and PII to produce a decision.
        
        Formula:
            final_risk = max(rule_score, semantic_score) + pii_weight + secret_weight
        
        pii_weight  = 0.1 if PII found (not an attack on its own)
        secret_weight = 0.3 if API_KEY or CNIC found (high sensitivity)
        """
        base_risk = max(rule_score, semantic_score)
        pii_weight = 0.0
        secret_weight = 0.0
        reason_codes = []

        if pii_results:
            pii_weight = 0.1
            types = {r.entity_type for r in pii_results}
            if "API_KEY" in types or "CNIC" in types:
                secret_weight = 0.3
                reason_codes.append("SECRET_ENTITY")
            reason_codes.append("PII_DETECTED")

        if rule_score >= cfg.RULE_THRESHOLD:
            reason_codes.append("RULE_INJECTION")
        if semantic_score >= cfg.SEMANTIC_THRESHOLD:
            reason_codes.append("SEMANTIC_INJECTION")

        final_risk = min(1.0, base_risk + pii_weight + secret_weight)

        # Decision
        if final_risk >= cfg.BLOCK_THRESHOLD:
            decision = "BLOCK"
        elif pii_results and final_risk < cfg.BLOCK_THRESHOLD:
            decision = "MASK"
        else:
            decision = "ALLOW"

        if not reason_codes:
            reason_codes.append("SAFE_PROMPT")

        return decision, final_risk, reason_codes