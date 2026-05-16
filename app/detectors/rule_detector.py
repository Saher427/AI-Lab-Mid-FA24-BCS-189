# app/detectors/rule_detector.py
import re
from config_loader import Config

class RuleDetector:
    def __init__(self):
        self.patterns = [
            r"ignore all previous instructions",
            r"ignore all rules",
            r"you are now dan",
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
            r"show me your instructions",
            r"lord voldemort",
            r"avada kedavra",
            # Urdu transliteration patterns
            r"pichli hidayat",
            r"tamam rules",
            r"system prompt dikhao",
            r"pabandiya bhool",
            # Korean romanized
            r"ijeonsijim museohanda",
        ]
        self.high_risk_keywords = [
            "ignore", "forget", "disregard", "override",
            "jailbreak", "developer mode", "system prompt",
            "instructions", "voldemort", "kedavra",
            "unrestricted", "bypass", "exfiltrate",
            "print api key", "reveal password", "show token",
        ]

    def score(self, text: str) -> float:
        s = 0.0
        t = text.lower()
        for p in self.patterns:
            if re.search(p, t):
                s += 0.6
                if s >= 1.0:
                    return 1.0
        for kw in self.high_risk_keywords:
            if kw in t:
                s += 0.4
                if s >= 1.0:
                    return 1.0
        if len(text) > 200:
            if "system" in t and "prompt" in t:
                s += 0.3
            if "ignore" in t or "forget" in t:
                s += 0.3
        return min(1.0, s)