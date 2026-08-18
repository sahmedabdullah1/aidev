from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(ROOT / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AI DevOps"
    app_env: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # OpenAI-compatible provider — default: Groq free tier (GPT-OSS 120B)
    # Get a free key: https://console.groq.com/keys
    llm_api_key: str = ""
    groq_api_key: str = ""  # alias — used when llm_api_key is empty
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_model: str = "openai/gpt-oss-120b"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 6000
    llm_evidence_max_chars: int = 28000
    enable_live_probe_default: bool = False
    require_llm: bool = True

    # GitLab
    gitlab_token: str = ""
    gitlab_webhook_secret: str = ""
    gitlab_url: str = "https://gitlab.com"

    # Storage
    workspace_dir: Path = DATA / "workspace"
    reports_dir: Path = DATA / "reports"
    uploads_dir: Path = DATA / "uploads"
    database_url: str = f"sqlite+aiosqlite:///{DATA / 'aidev.db'}"

    # Investigation limits
    max_clone_depth: int = 50
    max_file_bytes: int = 200_000
    max_files_scanned: int = 400
    max_log_bytes: int = 2_000_000
    wso2_max_log_bytes: int = 40_000_000  # production carbon logs are often 10-50MB

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    for path in (settings.workspace_dir, settings.reports_dir, settings.uploads_dir, DATA):
        path.mkdir(parents=True, exist_ok=True)
    return settings
