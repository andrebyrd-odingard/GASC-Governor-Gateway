from pydantic_settings import BaseSettings
import os

class Settings(BaseSettings):
    BACKEND_TYPE: str = "memory"
    MAX_TRAVERSAL_DEPTH: int = 1000
    OPA_URL: str | None = None # e.g. http://localhost:8181
    JWT_PUBLIC_KEY: str
    DEBUG_MODE: bool = False
    RECOVERY_ADAPTER_URL: str | None = None
    RECOVERY_ADAPTER_PUBLIC_KEY: str | None = None

settings = Settings()
