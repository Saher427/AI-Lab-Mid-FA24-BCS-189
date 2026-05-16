# app/utils/language.py
try:
    from langdetect import detect, LangDetectException
    LANGDETECT_AVAILABLE = True
except ImportError:
    LANGDETECT_AVAILABLE = False
    print("⚠️ langdetect not installed. Language detection disabled.")

# Urdu script range check
def contains_urdu(text: str) -> bool:
    for ch in text:
        if '\u0600' <= ch <= '\u06FF':
            return True
    return False

# Korean script range check
def contains_korean(text: str) -> bool:
    for ch in text:
        if '\uAC00' <= ch <= '\uD7A3':
            return True
    return False

def detect_language(text: str) -> str:
    """Return ISO 639-1 language code. Falls back to 'en' on error."""
    if contains_urdu(text):
        return "ur"
    if contains_korean(text):
        return "ko"
    if LANGDETECT_AVAILABLE:
        try:
            return detect(text)
        except Exception:
            pass
    return "en"