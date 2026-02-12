# Extracted from robortyan/nearai-private-chat (Open WebUI v0.6.5 fork)
# This shows how LLM endpoint is stored in DB and NOT in compose-hash

# ============================================================================
# 1. Config Model (stored in postgres, encrypted by seal-cvm)
# File: open_webui/config.py
# ============================================================================

class Config(Base):
    __tablename__ = "config"

    id = Column(Integer, primary_key=True)
    data = Column(JSON, nullable=False)  # <-- ALL settings stored here as JSON
    version = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================================
# 2. Reading config from DB
# File: open_webui/config.py
# ============================================================================

def get_config():
    with get_db() as db:
        config_entry = db.query(Config).order_by(Config.id.desc()).first()
        return config_entry.data if config_entry else DEFAULT_CONFIG

CONFIG_DATA = get_config()  # Loaded at startup from DB

def get_config_value(config_path: str):
    """Get a nested config value like 'openai.api_base_urls'"""
    path_parts = config_path.split(".")
    cur_config = CONFIG_DATA
    for key in path_parts:
        if key in cur_config:
            cur_config = cur_config[key]
        else:
            return None
    return cur_config


# ============================================================================
# 3. PersistentConfig - wrapper that reads from DB or falls back to env
# File: open_webui/config.py
# ============================================================================

class PersistentConfig(Generic[T]):
    def __init__(self, env_name: str, config_path: str, env_value: T):
        self.env_name = env_name
        self.config_path = config_path
        self.env_value = env_value
        self.config_value = get_config_value(config_path)  # <-- Reads from DB

        if self.config_value is not None and ENABLE_PERSISTENT_CONFIG:
            log.info(f"'{env_name}' loaded from the latest database entry")
            self.value = self.config_value  # <-- Use DB value
        else:
            self.value = env_value  # <-- Fall back to env var


# ============================================================================
# 4. OpenAI endpoint configuration
# File: open_webui/config.py
# ============================================================================

# Default if not set
OPENAI_API_BASE_URL = os.environ.get("OPENAI_API_BASE_URL", "")
if OPENAI_API_BASE_URL == "":
    OPENAI_API_BASE_URL = "https://api.openai.com/v1"  # <-- DEFAULT IS OPENAI!

# List of endpoints (can have multiple)
OPENAI_API_BASE_URLS = os.environ.get("OPENAI_API_BASE_URLS", "")
OPENAI_API_BASE_URLS = (
    OPENAI_API_BASE_URLS if OPENAI_API_BASE_URLS != "" else OPENAI_API_BASE_URL
)
OPENAI_API_BASE_URLS = [
    url.strip() if url != "" else "https://api.openai.com/v1"
    for url in OPENAI_API_BASE_URLS.split(";")
]

# THIS IS THE KEY LINE - wraps in PersistentConfig to read from DB
OPENAI_API_BASE_URLS = PersistentConfig(
    "OPENAI_API_BASE_URLS",      # env var name
    "openai.api_base_urls",       # DB path: config.data["openai"]["api_base_urls"]
    OPENAI_API_BASE_URLS          # fallback value
)

# Usage elsewhere in code:
# endpoint = OPENAI_API_BASE_URLS.value[0]  # Gets URL from DB


# ============================================================================
# 5. Saving config (when admin changes settings in UI)
# File: open_webui/config.py
# ============================================================================

def save_to_db(data):
    with get_db() as db:
        existing_config = db.query(Config).first()
        if not existing_config:
            new_config = Config(data=data, version=0)
            db.add(new_config)
        else:
            existing_config.data = data  # <-- Admin's changes saved here
            existing_config.updated_at = datetime.now()
            db.add(existing_config)
        db.commit()

def save_config(config):
    global CONFIG_DATA
    global PERSISTENT_CONFIG_REGISTRY
    try:
        save_to_db(config)  # <-- Writes to DB (encrypted by seal-cvm)
        CONFIG_DATA = config

        # Trigger updates on all registered PersistentConfig entries
        for config_item in PERSISTENT_CONFIG_REGISTRY:
            config_item.update()
    except Exception as e:
        log.exception(e)
        return False
    return True


# ============================================================================
# AUDIT SUMMARY
# ============================================================================
#
# The LLM endpoint flow:
#
# 1. Admin logs into Open WebUI
# 2. Admin goes to Settings → Connections → OpenAI
# 3. Admin types URL (e.g., "https://tee-inference.near.ai/v1")
# 4. save_config() is called → save_to_db() → Config table in postgres
# 5. Config table is encrypted by seal-cvm (AES-256-GCM)
# 6. On next request, OPENAI_API_BASE_URLS.value reads from DB
# 7. Chat request sent to that URL
#
# TRUST GAP:
# - The URL is NOT in compose-hash (it's runtime config in DB)
# - Users cannot verify which URL is configured
# - Admin could set it to api.openai.com (not private) or honeypot
# - Attestation proves CODE is correct, not CONFIGURATION
#
# DEFAULT IS OPENAI:
# - If admin doesn't configure anything, default is "https://api.openai.com/v1"
# - This would NOT be private!
