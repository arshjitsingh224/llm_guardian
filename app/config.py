from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    groq_api_key: str
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "llm_guardian"
    rules_path: str = "rules/default_rules.yaml"
    log_level: str = "INFO"
    groq_judge_model: str = "llama-3.1-8b-instant"


settings = Settings()
