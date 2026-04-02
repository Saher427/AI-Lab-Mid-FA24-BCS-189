# app/config.py
import yaml

class Config:
    # Default values
    INJECTION_THRESHOLD = 0.25
    POLICY = "Mask"
    ALLOWED_POLICIES = ["Allow", "Mask", "Block"]
    CUSTOM_ENTITIES = ["PHONE_NUMBER", "API_KEY", "INTERNAL_ID", "EMAIL", "COMPOSITE_CONTACT"]
    
    @classmethod
    def load(cls):
        """Load configuration from config.yaml if it exists"""
        try:
            with open("config.yaml", "r") as f:
                data = yaml.safe_load(f)
                if "INJECTION_THRESHOLD" in data:
                    cls.INJECTION_THRESHOLD = float(data["INJECTION_THRESHOLD"])
                if "POLICY" in data:
                    cls.POLICY = data["POLICY"]
            print(f"✅ Config loaded: INJECTION_THRESHOLD={cls.INJECTION_THRESHOLD}, POLICY={cls.POLICY}")
        except FileNotFoundError:
            print(f"⚠️ config.yaml not found, using defaults")
        except Exception as e:
            print(f"⚠️ Error loading config: {e}")