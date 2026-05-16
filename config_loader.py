# config_loader.py
import yaml

class Config:
    # Defaults
    RULE_THRESHOLD     = 0.25
    SEMANTIC_THRESHOLD = 0.55
    BLOCK_THRESHOLD    = 0.55
    POLICY             = "Mask"

    @classmethod
    def load(cls, path="config/gateway_config.yaml"):
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            cls.RULE_THRESHOLD     = float(data.get("RULE_THRESHOLD",     cls.RULE_THRESHOLD))
            cls.SEMANTIC_THRESHOLD = float(data.get("SEMANTIC_THRESHOLD", cls.SEMANTIC_THRESHOLD))
            cls.BLOCK_THRESHOLD    = float(data.get("BLOCK_THRESHOLD",    cls.BLOCK_THRESHOLD))
            cls.POLICY             = data.get("POLICY", cls.POLICY)
            print(f"✅ Config loaded: RULE={cls.RULE_THRESHOLD} SEMANTIC={cls.SEMANTIC_THRESHOLD} BLOCK={cls.BLOCK_THRESHOLD} POLICY={cls.POLICY}")
        except FileNotFoundError:
            print("⚠️ Config file not found, using defaults")
        except Exception as e:
            print(f"⚠️ Config error: {e}")