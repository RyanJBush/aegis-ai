from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    app_name: str = "Aegis AI API"
    environment: str = Field(default="development", alias="ENVIRONMENT")
    api_v1_prefix: str = "/api/v1"
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    postgres_host: str = Field(default="localhost", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_user: str = Field(default="aegis", alias="POSTGRES_USER")
    postgres_password: str = Field(default="aegis", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="aegis", alias="POSTGRES_DB")

    jwt_secret_key: str = Field(default="CHANGE_ME_IN_PROD", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_minutes: int = 60 * 24 * 7

    max_failed_login_attempts: int = 5
    account_lockout_minutes: int = 15
    auth_rate_limit_per_minute: int = 60
    alert_webhook_url: str | None = Field(default=None, alias="ALERT_WEBHOOK_URL")

    cors_origins: list[str] = ["http://localhost:3000"]

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
