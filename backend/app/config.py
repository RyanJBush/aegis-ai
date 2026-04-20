import os


class Settings:
    app_name: str = "Aegis AI"
    jwt_secret: str = os.getenv("JWT_SECRET", "change-me-in-development")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./aegis.db")
    frontend_origin: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    llm_api_url: str | None = os.getenv("LLM_API_URL")
    llm_api_key: str | None = os.getenv("LLM_API_KEY")


settings = Settings()
