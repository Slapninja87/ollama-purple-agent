"""
Conditional edge routing functions for the ollama-purple-agent LangGraph.

Each function receives the current PurpleAgentState and returns the name
of the next node to invoke. These implement the retry logic, bypass
detection, exhaustion checks, and hardening re-test loop from the
architecture flowchart.
"""

from __future__ import annotations

import structlog
from typing import Literal
from langgraph.graph import END

from src.graph.state import PurpleAgentState

logger = structlog.get_logger(__name__)

NextNode = str
MAX_RETRIES = 3


# ────────────────────────────────────────────────────────────────────────
# Phase Validation Routing
# ────────────────────────────────────────────────────────────────────────

def route_after_validate(state: PurpleAgentState) -> NextNode:
    phase = state.phase
    # Issue 1 Fixed: Accessing directly. Fails loudly if state is missing.
    passed = state.validation_passed 
    retries = state.retry_count

    if passed:
        if phase == "recon_complete":
            logger.info("route_after_validate: recon valid → enumerate")
            return "enumerate_node"
        elif phase == "enumeration_complete":
            logger.info("route_after_validate: enumeration valid → attack")
            return "attack_node"
        else:
            logger.info("route_after_validate: unknown pass-through → attack_node")
            return "attack_node"

    # Validation failed — retry
    if retries < MAX_RETRIES:
        if phase == "recon_complete":
            logger.warning("route_after_validate: recon retry", retry=retries, max_retries=MAX_RETRIES)
            return "recon_node"
        elif phase == "enumeration_complete":
            logger.warning("route_after_validate: enumeration retry", retry=retries, max_retries=MAX_RETRIES)
            return "enumerate_node"
        
        logger.error(f"route_after_validate: invalid phase for retry ({phase}) → report")
        return "report_node"

    # Max retries exhausted
    logger.error("route_after_validate: max retries exhausted, proceeding", phase=phase, retries=retries)

    if phase == "recon_complete":
        logger.error("route_after_validate: recon exhausted without valid profile → report")
        return "report_node"

    if phase == "enumeration_complete" and not state.vector_queue:
        return "report_node"

    return "attack_node"


# ────────────────────────────────────────────────────────────────────────
# Post-Attack Routing
# ────────────────────────────────────────────────────────────────────────

def route_after_attack(state: PurpleAgentState) -> NextNode:
    if state.phase == "attack_exhausted":
        logger.info("route_after_attack: all vectors exhausted → report")
        return "report_node"

    if not state.active_vector:
        if state.vector_queue:
            logger.info("route_after_attack: vector exhausted, queue has more → attack")
            return "attack_node"
        logger.info("route_after_attack: no active vector, queue empty → report")
        return "report_node"

    logger.info("route_after_attack: payload fired → judge", vector_class=state.active_vector.vector_class)
    return "judge_node"


# ────────────────────────────────────────────────────────────────────────
# Post-Judge Routing (Bypass vs. Held)
# ────────────────────────────────────────────────────────────────────────

def route_after_judge(state: PurpleAgentState) -> NextNode:
    if not state.findings:
        logger.warning("route_after_judge: no findings → attack")
        return "attack_node"

    latest = state.findings[-1]

    # Issue 2 Fixed: Routing to remediation on any confirmed bypass (score >= 1)
    if latest.bypass_confirmed:
        logger.info(
            "route_after_judge: bypass confirmed → remediate",
            score=latest.score,
            vector_class=latest.vector.vector_class,
        )
        return "remediate_node"

    logger.info("route_after_judge: guardrail held → next attack", score=latest.score)
    return "attack_node"


# ────────────────────────────────────────────────────────────────────────
# Post-Remediation Routing
# ────────────────────────────────────────────────────────────────────────

def route_after_remediate(state: PurpleAgentState) -> NextNode:
    if state.phase == "remediate_complete":
        logger.info("route_after_remediate: patch generated → harden")
        return "harden_node"

    logger.info("route_after_remediate: no patch needed → attack")
    return "attack_node"


# ────────────────────────────────────────────────────────────────────────
# Post-Hardening Routing (Re-Test Loop)
# ────────────────────────────────────────────────────────────────────────

def route_after_harden(state: PurpleAgentState) -> NextNode:
    logger.info("route_after_harden: hardening complete → re-test attack")
    return "attack_node"


# ────────────────────────────────────────────────────────────────────────
# Terminal Condition
# ────────────────────────────────────────────────────────────────────────

def should_continue(state: PurpleAgentState) -> NextNode:
    # Issue 3 Fixed: Returning END or a valid node name instead of a generic string
    if state.phase == "report_complete":
        return END

    attack_phases = state.phase_history.count("attack") if hasattr(state, 'phase_history') else 0
    if attack_phases > 50:
        logger.error("should_continue: attack loop safety limit reached")
        return END

    return "attack_node"