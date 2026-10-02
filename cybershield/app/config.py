from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    secret_key: str = "dev-secret-change-me"
    database_url: str = "sqlite:///./cybershield.db"
    access_token_expire_minutes: int = 120
    algorithm: str = "HS256"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    class Config:
        env_file = ".env"


settings = Settings()
