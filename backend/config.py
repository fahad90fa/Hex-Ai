"""Application configuration via Pydantic BaseSettings."""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://nexus:nexus_pass@localhost:5432/nexus_db",
        description="Async PostgreSQL connection URL",
    )

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )

    # Neo4j
    neo4j_uri: str = Field(default="bolt://localhost:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="nexus_neo4j")

    # Anthropic / Claude
    anthropic_api_key: str = Field(default="", description="Anthropic API key")

    # Security
    secret_key: str = Field(default="change-me-in-production-random-256-bit")

    # Server
    backend_port: int = Field(default=8000)
    debug: bool = Field(default=False)

    # Data storage
    data_dir: str = Field(default="data")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
