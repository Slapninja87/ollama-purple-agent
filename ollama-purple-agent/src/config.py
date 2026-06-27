from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class AppConfig(BaseSettings):
    # --- MODEL ASSIGNMENTS ---
    ATTACKER_MODEL: str = Field(default="qwen2.5-coder:14b")
    TARGET_MODEL: str = Field(default="llama3.1:8b")
    JUDGE_MODEL: str = Field(default="nemotron-3-super:cloud")
    
    # --- EDGE ROUTING FLAGS & ENDPOINTS ---
    JUDGE_IS_CLOUD: bool = Field(default=True, description="Toggles graph instantiation between local Ollama and cloud client wrappers.")
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434")
    CLOUD_BASE_URL: str | None = Field(default=None, description="Optional if bypassing local Ollama daemon entirely.")
    
    # --- PLAIN TEXT SECRETS GATEWAY ---
    CLOUD_API_KEY: str | None = Field(default=None)

    # --- CENTRALIZED PROMPT ASSET PATHS ---
    JUDGE_PROMPT_PATH: str = Field(default="config/prompts/judge_evaluate.txt")
    JUDGE_REMEDIATE_PROMPT_PATH: str = Field(default="config/prompts/judge_remediate.txt")
    ATTACKER_RECON_PROMPT_PATH: str = Field(default="config/prompts/attacker_recon.txt")
    ATTACKER_RECON_EXTRACT_PROMPT_PATH: str = Field(default="config/prompts/attacker_recon_extract.txt")
    ATTACKER_ENUMERATE_PROMPT_PATH: str = Field(default="config/prompts/attacker_enumerate.txt")
    ATTACKER_ATTACK_PROMPT_PATH: str = Field(default="config/prompts/attacker_attack.txt")
    TARGET_SYSTEM_PROMPT_PATH: str = Field(default="config/prompts/target_system.txt")
    REPORT_PROMPT_PATH: str = Field(default="config/prompts/report_generate.txt")

    # --- PYDANTIC SETTINGS V2 ENGINE CONFIGURATION ---
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        extra="ignore"
    )

    # --- ENFORCE KEY PRESENCE IF CLOUD IS ACTIVE ---
    @model_validator(mode="after")
    def validate_cloud_credentials(self) -> "AppConfig":
        # If your execution engine bypasses local Ollama and hits an external API directly,
        # this ensures you don't spin up an invalid graph state.
        if self.JUDGE_IS_CLOUD and not self.CLOUD_API_KEY and self.CLOUD_BASE_URL:
            raise ValueError(
                "JUDGE_IS_CLOUD is enabled with an explicit CLOUD_BASE_URL, but CLOUD_API_KEY is missing from environment/config."
            )
        return self

# Instantiate a global singleton instance for the app to import
config = AppConfig()