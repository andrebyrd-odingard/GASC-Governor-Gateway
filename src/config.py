from pydantic_settings import BaseSettings
import os
from typing import Optional

class Settings(BaseSettings):
    BACKEND_TYPE: str = "memory"
    MAX_TRAVERSAL_DEPTH: int = 1000
    OPA_URL: str | None = None # e.g. http://localhost:8181
    JWT_PUBLIC_KEY: str
    DEBUG_MODE: bool = False
    # Recovery Settings
    RECOVERY_ADAPTER_URL: Optional[str] = None
    
    # Shadow Mode Settings
    ENFORCEMENT_MODE: str = "shadow"
    SHADOW_BANNER: bool = True
    
    # OPA Settings
    OPA_POLICY_BUNDLE: Optional[str] = None
    RECOVERY_ADAPTER_PUBLIC_KEY: str | None = None
    CONTINUATION_HORIZON_SECONDS: int = 86400
    MAX_WITHDRAWAL_AMPLIFICATION: int = 100
    RECURRENCE_SIGNAL_RATE_LIMIT: int = 10
    RECURRENCE_SIGNAL_GLOBAL_LIMIT: int = 100
    DESIGNATION_RATE_LIMIT: int = 20
    TRUST_RENEWAL_REQUIRED: bool = True

settings = Settings()
