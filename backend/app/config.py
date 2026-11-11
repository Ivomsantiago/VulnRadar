from pathlib import Path
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AccessKey(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    role: Literal["viewer", "analyst", "admin"]
    expires_at: datetime


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNRADAR_", env_file=".env", extra="ignore", hide_input_in_errors=True)
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
    notification_channel: Literal["webhook", "smtp"] = "webhook"
    smtp_host: str | None = None
    smtp_allowed_hosts: list[str] = []
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_sender: str | None = None
    smtp_recipients: list[str] = []
    nvd_api_key: str | None = None
    github_token: str | None = None
    max_file_bytes: int = 5_000_000
    max_scan_bytes: int = 100_000_000
    max_files: int = 2000
    max_components: int = Field(20000, ge=100, le=50000)
    scan_timeout: int = 120
    oci_timeout: int = 600
    oci_registries: list[str] = ["docker.io", "registry-1.docker.io", "ghcr.io", "quay.io"]
    osv_batch: bool = True
    access_mode: Literal["local", "team"] = "local"
    access_keys: dict[str, AccessKey] = {}
    session_minutes: int = Field(480, ge=5, le=1440)
    session_idle_minutes: int = Field(30, ge=1, le=60)
    max_sessions: int = Field(256, ge=1, le=1000)
    max_sessions_per_key: int = Field(4, ge=1, le=32)
    requests_per_minute: int = Field(600, ge=10, le=60000)
    mutations_per_minute: int = Field(60, ge=1, le=6000)
    osv_queries_enabled: bool = False
    max_upstream_bytes: int = Field(30_000_000, ge=1024, le=100_000_000)
    store_code_snippets: bool = False
    allow_local_sast_in_team: bool = False
    request_timeout: int = Field(30, ge=1, le=120)
    nvd_backfill_days: Literal[7, 30, 90] = 7
    retention_progress_days: int = Field(0, ge=0, le=3650)
    retention_delivery_days: int = Field(0, ge=0, le=3650)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @model_validator(mode="after")
    def deployment_policy(self):
        if self.notification_channel == "smtp":
            import re
            if not self.smtp_host or self.smtp_host not in self.smtp_allowed_hosts or not self.smtp_sender or not 1 <= len(self.smtp_recipients) <= 10:
                raise ValueError("SMTP exige host autorizado, remetente e 1-10 destinatários")
            for address in [self.smtp_sender, *self.smtp_recipients]:
                if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", address):
                    raise ValueError("SMTP exige endereços simples válidos, sem nomes ou quebras de linha")
            if bool(self.smtp_username) != bool(self.smtp_password):
                raise ValueError("SMTP exige usuário e credencial em conjunto")
        if self.access_mode == "team":
            if not self.access_keys:
                raise ValueError("Modo team exige chaves pessoais configuradas")
            if any("*" in value for value in self.allowed_hosts + self.origins):
                raise ValueError("Modo team exige hosts e origens explícitos")
            if not self.origins or any(not value.startswith("https://") for value in self.origins):
                raise ValueError("Modo team exige origens HTTPS")
        for name, key in self.access_keys.items():
            if not name or len(name) > 80 or any(not (char.isascii() and (char.isalnum() or char in "_.-")) for char in name):
                raise ValueError("Identificador de acesso inválido")
            if key.expires_at.tzinfo is None:
                raise ValueError("Validade da chave exige fuso horário")
        return self
    frontend_dist: Path = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    semgrep_rules: Path = Path(__file__).resolve().parents[2] / "rules" / "semgrep"


settings = Settings()
