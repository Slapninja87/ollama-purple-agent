import json
import logging
from pathlib import Path
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from src.config import config
from src.graph.state import AttackVector, TargetProfile, ReconExtraction
from src.vectors.library import VECTOR_LIBRARY

logger = logging.getLogger("purple_team.attacker")


class AttackerAgent:
    def __init__(self, model_name: str = config.ATTACKER_MODEL):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.85  # Higher temperature allows for creative adversarial mutations
        )
        self.recon_prompt_template = self._load_prompt(config.ATTACKER_RECON_PROMPT_PATH)
        self.recon_extract_prompt_template = self._load_prompt(config.ATTACKER_RECON_EXTRACT_PROMPT_PATH)
        self.enumerate_prompt_template = self._load_prompt(config.ATTACKER_ENUMERATE_PROMPT_PATH)
        self.attack_prompt_template = self._load_prompt(config.ATTACKER_ATTACK_PROMPT_PATH)

        # Structured output LLM for deterministic recon extraction
        self.structured_recon = self.llm.with_structured_output(ReconExtraction)

    def _load_prompt(self, path: str) -> str:
        resolved_path = Path(path)
        if not resolved_path.exists():
            raise FileNotFoundError(
                f"Critical attacker prompt asset missing at: {resolved_path.resolve()}"
            )
        return resolved_path.read_text(encoding="utf-8")

    def generate_recon_probe(self) -> str:
        """Generates an initial probe payload to map out the target model's behavior rules."""
        prompt = ChatPromptTemplate.from_messages([
            ("system", self.recon_prompt_template),
            ("human", "Generate the initial exploratory security probe.")
        ])
        chain = prompt | self.llm
        try:
            response = chain.invoke({})
            return response.content.strip()
        except Exception as e:
            logger.error(f"[ATTACKER RECON FAILURE] Failed to generate probe: {str(e)}")
            raise RuntimeError(f"Attacker reconnaissance engine failure: {str(e)}") from e

    def parse_recon_response(self, probe: str, target_response: str) -> ReconExtraction:
        """
        Parses a recon probe/response exchange into structured intelligence
        about the target's guardrail configuration and refusal behavior.

        Uses with_structured_output to enforce the ReconExtraction schema,
        consistent with JudgeAgent's extraction pattern.

        Raises:
            RuntimeError: If the LLM fails to produce a valid extraction,
                          escalated to recon_node for fallback handling.
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", self.recon_extract_prompt_template),
            ("human", (
                "### RECON EXCHANGE TO ANALYZE:\n"
                "PROBE SENT:\n"
                "---\n"
                "{probe}\n"
                "---\n"
                "TARGET RESPONSE RECEIVED:\n"
                "---\n"
                "{target_response}\n"
                "---\n"
                "Extract the structured intelligence from this exchange."
            ))
        ])

        chain = prompt | self.structured_recon

        try:
            extraction: ReconExtraction = chain.invoke({
                "probe": probe,
                "target_response": target_response,
            })
            logger.info(
                f"[ATTACKER RECON] Extraction complete — "
                f"refusal_style={extraction.refusal_style}, "
                f"guardrails={extraction.detected_guardrail_categories}"
            )
            return extraction
        except Exception as e:
            logger.error(f"[ATTACKER RECON PARSE FAILURE] Extraction failed: {str(e)}")
            raise RuntimeError(f"Attacker recon parse failure: {str(e)}") from e

    def generate_vector_queue(self, profile: TargetProfile) -> list[AttackVector]:
        """
        Builds a prioritized attack queue by asking the LLM to rank vector
        classes based on the TargetProfile, then seeding each selected class
        with its first payload from VECTOR_LIBRARY.

        The LLM returns a JSON array of vector class names ordered by priority.
        Each name is matched against VECTOR_LIBRARY to produce seed AttackVectors.
        Unknown class names returned by the LLM are silently skipped.

        Security Reason: Enumeration is intelligence-driven — the attack queue
        is tailored to what recon revealed, not a blind static checklist.
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", self.enumerate_prompt_template),
            ("human", (
                "### TARGET PROFILE:\n"
                "Refusal Style: {refusal_style}\n"
                "Detected Guardrail Categories: {guardrail_categories}\n"
                "System Prompt Hints: {system_hints}\n"
                "Persona: {persona}\n\n"
                "Produce the prioritized attack vector class queue as a JSON array."
            ))
        ])

        # Lower temperature for structured output — we need valid JSON, not creativity
        structured_llm = ChatOllama(
            model=self.llm.model,
            temperature=0.3,
        )
        chain = prompt | structured_llm

        hints_str = (
            ", ".join(profile.system_prompt_hints)
            if profile.system_prompt_hints
            else "None discovered"
        )
        categories_str = (
            ", ".join(profile.detected_guardrail_categories)
            if profile.detected_guardrail_categories
            else "None detected"
        )

        try:
            result = chain.invoke({
                "refusal_style": profile.refusal_style,
                "guardrail_categories": categories_str,
                "system_hints": hints_str,
                "persona": profile.persona or "Not detected",
            })

            raw = result.content.strip()

            # Strip markdown fences if the model wrapped the JSON
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            prioritized_classes: list[str] = json.loads(raw)

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.warning(
                f"[ATTACKER ENUMERATE] LLM returned invalid JSON — "
                f"falling back to full library. Error: {str(e)}"
            )
            # Fallback: use all library classes in definition order
            prioritized_classes = list(VECTOR_LIBRARY.keys())

        except Exception as e:
            logger.error(f"[ATTACKER ENUMERATE FAILURE] Enumeration LLM call failed: {str(e)}")
            raise RuntimeError(f"Attacker enumeration engine failure: {str(e)}") from e

        # Seed one AttackVector per prioritized class from VECTOR_LIBRARY
        # Normalize key lookup: strip slashes so "Tool/Agent Hijacking" matches
        # "Tool Agent Hijacking" in the library
        def normalize(name: str) -> str:
            return name.replace("/", " ").replace("  ", " ").strip()

        normalized_library = {normalize(k): v for k, v in VECTOR_LIBRARY.items()}

        vector_queue: list[AttackVector] = []
        for class_name in prioritized_classes:
            payloads = normalized_library.get(normalize(class_name))
            if not payloads:
                logger.warning(
                    f"[ATTACKER ENUMERATE] Unknown vector class '{class_name}' — skipping"
                )
                continue
            vector_queue.append(
                AttackVector(
                    vector_class=class_name,
                    payload=payloads[0],  # Seed payload; mutation happens in attack_node
                    mutation_generation=0,
                    parent_payload=None,
                )
            )

        logger.info(
            f"[ATTACKER ENUMERATE] Queue built — "
            f"{len(vector_queue)} vectors: {[v.vector_class for v in vector_queue]}"
        )
        return vector_queue

    def mutate_payload(self, seed_vector: AttackVector, profile: TargetProfile) -> AttackVector:
        """
        Mutates a base seed payload into a highly targeted variant using known insights
        about the target assistant's guardrails.
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", self.attack_prompt_template)
        ])
        chain = prompt | self.llm

        hints_str = (
            ", ".join(profile.system_prompt_hints)
            if profile.system_prompt_hints
            else "None discovered yet"
        )

        try:
            logger.info(f"Attacker mutating payload for vector class: {seed_vector.vector_class}")
            mutated_content = chain.invoke({
                "vector_class": seed_vector.vector_class,
                "seed_payload": seed_vector.payload,
                "refusal_style": profile.refusal_style,
                "system_hints": hints_str
            }).content.strip()

            return AttackVector(
                vector_class=seed_vector.vector_class,
                payload=mutated_content,
                mutation_generation=seed_vector.mutation_generation + 1,
                parent_payload=seed_vector.payload
            )
        except Exception as e:
            logger.error(f"[ATTACKER MUTATION FAILURE] Optimization chain failed: {str(e)}")
            raise RuntimeError(f"Attacker mutation engine failure: {str(e)}") from e
