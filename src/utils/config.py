"""
Configuration management for the threat hunting platform.
Supports loading from YAML files and environment variables.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from loguru import logger


class DatabaseConfig(BaseModel):
    """Database configuration settings."""
    host: str = "localhost"
    port: int = 5432
    database: str = "threat_hunting"
    user: str = "threat_hunter"
    password: str = "changeme"
    pool_size: int = 10
    max_overflow: int = 20


class RedisConfig(BaseModel):
    """Redis configuration settings."""
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    db: int = 0
    max_connections: int = 50


class KafkaConfig(BaseModel):
    """Kafka configuration settings."""
    bootstrap_servers: str = "localhost:9092"
    consumer_group: str = "threat-hunting-platform"
    topics: Dict[str, str] = Field(default_factory=lambda: {
        "events": "security-events",
        "anomalies": "anomalies",
        "leads": "threat-leads"
    })


class MLConfig(BaseModel):
    """Machine learning configuration settings."""
    model_path: str = "models/trained"
    baseline_path: str = "models/baselines"
    anomaly_threshold: float = 0.95
    retrain_interval_hours: int = 24


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "threat-hunting-platform"
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = False
    log_level: str = "INFO"

    # Database
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "threat_hunting"
    postgres_user: str = "threat_hunter"
    postgres_password: str = "changeme"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: Optional[str] = None

    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"

    # API
    api_secret_key: str = "changeme_generate_secure_random_key"

    class Config:
        env_file = ".env"
        case_sensitive = False


class ConfigManager:
    """Manages configuration from YAML files and environment variables."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to YAML configuration file
        """
        self.settings = Settings()
        self.config_data: Dict[str, Any] = {}

        if config_path:
            self.load_config(config_path)
        else:
            # Auto-detect config based on environment
            env = os.getenv("APP_ENV", "development")
            default_path = f"config/{env}.yaml"
            if Path(default_path).exists():
                self.load_config(default_path)

    def load_config(self, config_path: str) -> None:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to YAML configuration file
        """
        try:
            with open(config_path, 'r') as f:
                self.config_data = yaml.safe_load(f)

            # Expand environment variables in config
            self.config_data = self._expand_env_vars(self.config_data)

            logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            raise

    def _expand_env_vars(self, data: Any) -> Any:
        """
        Recursively expand environment variables in configuration.

        Args:
            data: Configuration data (dict, list, or string)

        Returns:
            Data with environment variables expanded
        """
        if isinstance(data, dict):
            return {k: self._expand_env_vars(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._expand_env_vars(item) for item in data]
        elif isinstance(data, str) and data.startswith("${") and data.endswith("}"):
            # Extract environment variable name and optional default
            env_expr = data[2:-1]
            if ":-" in env_expr:
                env_var, default = env_expr.split(":-", 1)
                return os.getenv(env_var, default)
            else:
                return os.getenv(env_expr, data)
        return data

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key.

        Args:
            key: Configuration key (e.g., 'database.postgres.host')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config_data

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration."""
        db_config = self.get('database.postgres', {})
        return DatabaseConfig(
            host=db_config.get('host', self.settings.postgres_host),
            port=db_config.get('port', self.settings.postgres_port),
            database=db_config.get('database', self.settings.postgres_db),
            user=db_config.get('user', self.settings.postgres_user),
            password=db_config.get('password', self.settings.postgres_password),
            pool_size=db_config.get('pool_size', 10),
            max_overflow=db_config.get('max_overflow', 20)
        )

    def get_redis_config(self) -> RedisConfig:
        """Get Redis configuration."""
        redis_config = self.get('streaming.redis', {})
        return RedisConfig(
            host=redis_config.get('host', self.settings.redis_host),
            port=redis_config.get('port', self.settings.redis_port),
            password=redis_config.get('password', self.settings.redis_password),
            db=redis_config.get('db', 0),
            max_connections=redis_config.get('max_connections', 50)
        )

    def get_kafka_config(self) -> KafkaConfig:
        """Get Kafka configuration."""
        kafka_config = self.get('streaming.kafka', {})
        return KafkaConfig(
            bootstrap_servers=kafka_config.get('bootstrap_servers', self.settings.kafka_bootstrap_servers),
            consumer_group=kafka_config.get('consumer_group', 'threat-hunting-platform'),
            topics=kafka_config.get('topics', {})
        )

    def get_ml_config(self) -> MLConfig:
        """Get machine learning configuration."""
        ml_config = self.get('analytics', {})
        return MLConfig(
            model_path=ml_config.get('model_path', 'models/trained'),
            baseline_path=ml_config.get('baseline_path', 'models/baselines'),
            anomaly_threshold=ml_config.get('anomaly_threshold', 0.95),
            retrain_interval_hours=ml_config.get('training', {}).get('retrain_interval_hours', 24)
        )


# Global configuration instance
config = ConfigManager()
