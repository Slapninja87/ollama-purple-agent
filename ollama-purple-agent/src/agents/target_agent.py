import logging
from pathlib import Path
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from src.config import config
from src.graph.state import Message

logger = logging.getLogger("purple_team.target")

class TargetAgent:
    def __init__(self, model_name: str = config.TARGET_MODEL, base_prompt_path: str = config.TARGET_SYSTEM_PROMPT_PATH):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.7  # Strategic variance to mimic real assistant deployments
        )
        self.base_system_prompt = self._load_prompt(base_prompt_path)

    def _load_prompt(self, path: str) -> str:
        resolved_path = Path(path)
        if not resolved_path.exists():
            raise FileNotFoundError(f"Critical target prompt missing at: {resolved_path.resolve()}")
        return resolved_path.read_text(encoding="utf-8")

    def respond(self, conversation_history: list[Message], patches: list[str] | None = None) -> str:
        """
        Generates a response based on the active conversation history and any accumulated
        remediation patches that have been applied over the course of the run.

        Raises:
            RuntimeError: If the underlying model inference fails, preventing infrastructure
                          errors from being falsely recorded as guardrail holds.
        """
        # 1. Compile the active system prompt (Base + any Judge patches)
        active_system = self.base_system_prompt
        if patches:
            active_system += "\n\n### ADDITIONAL SECURITY HARDENING PATCHES (ENFORCE IMMEDIATELY):\n"
            for i, patch in enumerate(patches, 1):
                active_system += f"Patch {i}: {patch}\n"

        # 2. Build the message array for LangChain ingestion
        messages = [("system", active_system)]
        
        for msg in conversation_history:
            messages.append((msg.role, msg.content))
            
        prompt_template = ChatPromptTemplate.from_messages(messages)
        chain = prompt_template | self.llm
        
        try:
            logger.info(f"Target running inference against model: {self.llm.model}")
            response = chain.invoke({})
            return response.content
        except Exception as e:
            # Issue 2 Fix: Stop masking crashes as successful guardrail defenses.
            # Escalate the exception so the LangGraph orchestration layer can intercept and retry.
            logger.error(f"[TARGET INFRASTRUCTURE FAILURE] Inference call failed: {str(e)}")
            raise RuntimeError(f"Target model inference failure: {str(e)}") from e