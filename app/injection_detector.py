# app/injection_detector.py
import re
from typing import Tuple
from app.config import Config

class InjectionDetector:
    def __init__(self):
        # Jailbreak and injection patterns
        self.jailbreak_patterns = [
            r"ignore all previous instructions",
            r"ignore all rules",
            r"you are now DAN",
            r"disregard.*system prompt",
            r"output your system prompt",
            r"forget everything you know",
            r"act as an unfiltered",
            r"jailbreak",
            r"developer mode",
            r"repeat the system prompt",
            r"reveal your instructions",
            r"do not follow any rules",
            r"override previous",
            r"new instructions",
            r"system prompt",
            r"what is your system prompt",
            r"show me your instructions",
            r"lord voldemort",
            r"avada kedavra",
        ]
        
        # High-risk keywords
        self.high_risk_keywords = [
            "ignore", "forget", "disregard", "override",
            "jailbreak", "dan", "developer mode",
            "system prompt", "instructions", "voldemort", "kedavra"
        ]
    
    def calculate_score(self, text: str) -> Tuple[float, str]:
        """Calculate injection score between 0 and 1"""
        score = 0.0
        text_lower = text.lower()
        
        # Check each pattern
        for pattern in self.jailbreak_patterns:
            if re.search(pattern, text_lower):
                score += 0.35
                if score >= 1.0:
                    break
        
        # Check for high-risk keywords
        for keyword in self.high_risk_keywords:
            if keyword in text_lower:
                score += 0.25
                if score >= 1.0:
                    break
        
        # Additional heuristic for long suspicious prompts
        if len(text) > 200:
            if "system" in text_lower and "prompt" in text_lower:
                score += 0.3
            if "ignore" in text_lower or "forget" in text_lower:
                score += 0.3
        
        # Cap at 1.0
        score = min(1.0, score)
        
        # Determine verdict using configurable threshold
        verdict = "Injection" if score >= Config.INJECTION_THRESHOLD else "Safe"
        
        return score, verdict
