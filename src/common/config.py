"""Configuration management using Pydantic settings."""

from functools import lru_cache
from typing import Optional

from pydantic import Field, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "SBOM Security Platform"
    app_version: str = "0.1.0"
    debug: bool = Field(default=False, alias="DEBUG")
    environment: str = Field(default="development", alias="ENVIRONMENT")

    # Database
    database_url: PostgresDsn = Field(
        default="postgresql://sbom_user:sbom_pass@localhost:5432/sbom_db",
        alias="DATABASE_URL",
    )
    db_pool_size: int = Field(default=10, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=20, alias="DB_MAX_OVERFLOW")
    db_echo: bool = Field(default=False, alias="DB_ECHO")

    # Redis
    redis_url: RedisDsn = Field(
        default="redis://localhost:6379/0",
        alias="REDIS_URL",
    )
    cache_ttl: int = Field(default=3600, alias="CACHE_TTL")  # 1 hour

    # API
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_workers: int = Field(default=4, alias="API_WORKERS")
    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        alias="CORS_ORIGINS",
    )

    # Security
    secret_key: str = Field(
        default="change-me-in-production-use-openssl-rand-hex-32",
        alias="SECRET_KEY",
    )
    algorithm: str = Field(default="HS256", alias="ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=30,
        alias="ACCESS_TOKEN_EXPIRE_MINUTES",
    )

    # SBOM Processing
    max_sbom_size_mb: int = Field(default=50, alias="MAX_SBOM_SIZE_MB")
    max_components_per_sbom: int = Field(default=50000, alias="MAX_COMPONENTS_PER_SBOM")
    sbom_signature_required: bool = Field(default=False, alias="SBOM_SIGNATURE_REQUIRED")

    # Vulnerability Feeds
    nvd_api_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        alias="NVD_API_URL",
    )
    nvd_api_key: Optional[str] = Field(default=None, alias="NVD_API_KEY")
    osv_api_url: str = Field(default="https://api.osv.dev/v1", alias="OSV_API_URL")
    github_api_url: str = Field(
        default="https://api.github.com/advisories",
        alias="GITHUB_API_URL",
    )
    github_token: Optional[str] = Field(default=None, alias="GITHUB_TOKEN")

    # Risk Scoring Weights
    vulnerability_weight: float = Field(default=0.40, alias="VULNERABILITY_WEIGHT")
    license_risk_weight: float = Field(default=0.20, alias="LICENSE_RISK_WEIGHT")
    signing_weight: float = Field(default=0.20, alias="SIGNING_WEIGHT")
    maintainer_health_weight: float = Field(default=0.10, alias="MAINTAINER_HEALTH_WEIGHT")
    dependency_depth_weight: float = Field(default=0.10, alias="DEPENDENCY_DEPTH_WEIGHT")

    # Thresholds
    critical_risk_threshold: float = Field(default=8.0, alias="CRITICAL_RISK_THRESHOLD")
    high_risk_threshold: float = Field(default=6.0, alias="HIGH_RISK_THRESHOLD")
    medium_risk_threshold: float = Field(default=4.0, alias="MEDIUM_RISK_THRESHOLD")

    # Compliance
    slsa_level_required: int = Field(default=3, alias="SLSA_LEVEL_REQUIRED")
    ntia_validation_enabled: bool = Field(default=True, alias="NTIA_VALIDATION_ENABLED")

    # Performance
    scan_timeout_seconds: int = Field(default=300, alias="SCAN_TIMEOUT_SECONDS")
    max_concurrent_scans: int = Field(default=10, alias="MAX_CONCURRENT_SCANS")


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
