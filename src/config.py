from pydantic_settings import BaseSettings
import os
from typing import Optional

class Settings(BaseSettings):
    BACKEND_TYPE: str = "memory"  # "memory" | "sqlite" | "postgres"
    POSTGRES_DSN: str = ""
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

    # Readiness / Backpressure Settings
    READINESS_PROBE_PATH: str = "/ready"
    MAX_IN_FLIGHT_REQUESTS: int = 100
    GRACEFUL_DRAIN_TIMEOUT_SECONDS: float = 30.0

    # Benchmark / CI gate (can be overridden via BENCHMARK_P99_50_MS env var)
    BENCHMARK_P99_50_MS: float = 500.0

settings = Settings()
