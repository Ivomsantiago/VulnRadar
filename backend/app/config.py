from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNRADAR_", env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./data/vulnradar.db"
    allowed_roots: list[str] = []
    allowed_hosts: list[str] = ["127.0.0.1", "localhost", "testserver"]
    origins: list[str] = ["http://127.0.0.1:8000", "http://localhost:8000", "http://127.0.0.1:5173"]
    sync_minutes: int = 60
    auto_sync: bool = False
    webhook_url: str | None = None
    webhook_allowed_hosts: list[str] = []
    webhook_format: str = "generic"
    notification_interval_seconds: int = 60
    nvd_api_key: str | None = None
    github_token: str | None = None
    max_file_bytes: int = 5_000_000
    max_scan_bytes: int = 100_000_000
    max_files: int = 2000
    scan_timeout: int = 120
    frontend_dist: Path = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    semgrep_rules: Path = Path(__file__).resolve().parents[2] / "rules" / "semgrep"


settings = Settings()
