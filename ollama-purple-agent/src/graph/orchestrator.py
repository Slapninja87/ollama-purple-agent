"""
LangGraph StateGraph orchestrator for the ollama-purple-agent.

Constructs the full purple-team assessment pipeline as a compiled
LangGraph application. The graph implements:

  START → recon → validate → enumerate → validate → attack → judge
       ↻ retry         ↻ retry              ↓ (bypass)       ↓ (held)
                                        remediate → harden → attack (re-test)
                                                            ↓ (exhausted)
                                                          report → END

Usage:
    from src.graph.orchestrator import build_purple_graph, create_initial_state

    app = build_purple_graph()
    final_state = app.invoke(create_initial_state(
        target="llama3.1:8b",
        attacker_model="qwen2.5-coder:14b",
        judge_model="nemotron-super"
    ))

Security Reason: The orchestrator is the single source of truth for the
graph topology. Every edge is explicitly declared — no implicit routing.
This makes the attack chain auditable and prevents unintended phase
skipping or state leakage between assessments.
"""

from __future__ import annotations

import structlog
from typing import Any

from langgraph.graph import StateGraph, END

from src.graph.state import PurpleAgentState
from src.graph.nodes import (
    recon_node,
    validate_phase_node,
    enumerate_node,
    attack_node,
    judge_node,
    remediate_node,
    harden_node,
    report_node,
)
from src.graph.edges import (
    route_after_validate,
    route_after_attack,
    route_after_judge,
    route_after_remediate,
    # Fix 3: route_after_harden removed — harden uses a direct edge, not conditional
)

logger = structlog.get_logger(__name__)

# ────────────────────────────────────────────────────────────────────────
# Node name constants
# Single source of truth for graph topology — prevents silent string typos
# ────────────────────────────────────────────────────────────────────────

NODE_RECON      = "recon_node"
NODE_VALIDATE   = "validate_phase_node"
NODE_ENUMERATE  = "enumerate_node"
NODE_ATTACK     = "attack_node"
NODE_JUDGE      = "judge_node"
NODE_REMEDIATE  = "remediate_node"
NODE_HARDEN     = "harden_node"
NODE_REPORT     = "report_node"


def build_purple_graph() -> StateGraph:
    """
    Construct and compile the full purple-team LangGraph StateGraph.

    Returns a compiled StateGraph ready for invocation with an initial
    PurpleAgentState dict from create_initial_state().

    Graph topology:

        START ──→ recon_node
                     │
                     ▼
              validate_phase_node
                 ╱         ╲
          [retry]           [passed]
        recon_node        enumerate_node
                               │
                               ▼
                      validate_phase_node
                         ╱         ╲
                  [retry]           [passed]
              enumerate_node       attack_node
                                      │
                                      ▼
                                  judge_node
                                 ╱         ╲
                          [bypass]           [held]
                       remediate_node      attack_node
                             │                  ▲
                             ▼                  │
                         harden_node ───────────┘
                                      (re-test loop)
                                      │
                               [exhausted]
                                      │
                                      ▼
                                 report_node
                                      │
                                      ▼
                                     END

    Security Reason: The graph is constructed immutably — once compiled,
    the topology cannot be altered at runtime. This prevents injection
    attacks that might attempt to redirect the pipeline mid-assessment.
    """
    logger.info("build_purple_graph: constructing StateGraph")

    # ── Create the StateGraph with PurpleAgentState as the schema ──
    workflow = StateGraph(PurpleAgentState)

    # ── Register all nodes ──
    workflow.add_node(NODE_RECON,      recon_node)
    workflow.add_node(NODE_VALIDATE,   validate_phase_node)
    workflow.add_node(NODE_ENUMERATE,  enumerate_node)
    workflow.add_node(NODE_ATTACK,     attack_node)
    workflow.add_node(NODE_JUDGE,      judge_node)
    workflow.add_node(NODE_REMEDIATE,  remediate_node)
    workflow.add_node(NODE_HARDEN,     harden_node)
    workflow.add_node(NODE_REPORT,     report_node)

    # ── Set entry point ──
    workflow.set_entry_point(NODE_RECON)

    # ── Phase 1: Recon → Validate ──
    workflow.add_edge(NODE_RECON, NODE_VALIDATE)

    # ── Validation gate: routes to recon retry, enumerate, or attack ──
    workflow.add_conditional_edges(
        NODE_VALIDATE,
        route_after_validate,
        {
            NODE_RECON:      NODE_RECON,
            NODE_ENUMERATE:  NODE_ENUMERATE,
            NODE_ATTACK:     NODE_ATTACK,
            NODE_REPORT:     NODE_REPORT,   # Safety: exhausted retries with empty queue
        },
    )

    # ── Phase 2: Enumerate → Validate ──
    workflow.add_edge(NODE_ENUMERATE, NODE_VALIDATE)

    # ── Phase 3: Attack → Route (judge or report) ──
    workflow.add_conditional_edges(
        NODE_ATTACK,
        route_after_attack,
        {
            NODE_JUDGE:   NODE_JUDGE,
            NODE_REPORT:  NODE_REPORT,
            NODE_ATTACK:  NODE_ATTACK,  # Self-loop: advance to next vector after exhaustion
        },
    )

    # ── Phase 4: Judge → Route (remediate or re-attack) ──
    workflow.add_conditional_edges(
        NODE_JUDGE,
        route_after_judge,
        {
            NODE_REMEDIATE:  NODE_REMEDIATE,
            NODE_ATTACK:     NODE_ATTACK,
        },
    )

    # ── Phase 5: Remediate → Route (harden or re-attack) ──
    workflow.add_conditional_edges(
        NODE_REMEDIATE,
        route_after_remediate,
        {
            NODE_HARDEN:  NODE_HARDEN,
            NODE_ATTACK:  NODE_ATTACK,
        },
    )

    # ── Phase 5b: Harden → Attack (re-test loop, direct edge) ──
    # Fix 3: Direct edge — no conditional needed, harden always re-tests
    workflow.add_edge(NODE_HARDEN, NODE_ATTACK)

    # ── Terminal: Report → END ──
    workflow.add_edge(NODE_REPORT, END)

    # ── Compile ──
    logger.info("build_purple_graph: compiling graph")
    compiled = workflow.compile()
    logger.info("build_purple_graph: graph compiled successfully")

    return compiled


# ────────────────────────────────────────────────────────────────────────
# Convenience: create a clean initial state for graph invocation
# ────────────────────────────────────────────────────────────────────────

def create_initial_state(
    target: str,
    attacker_model: str,
    judge_model: str,
) -> dict[str, Any]:
    """
    Build a minimal, clean initial state dict for graph invocation.

    Args:
        target:          Ollama model name for the Target agent.
        attacker_model:  Ollama model name for the Attacker agent.
        judge_model:     Ollama model name for the Judge agent.

    Returns:
        A dict of initial state values suitable for app.invoke().

    Security Reason: All mutable collections are initialized as empty
    lists rather than shared references. target_profile is omitted so
    PurpleAgentState's default_factory constructs a clean TargetProfile.
    This prevents stale data from a previous run contaminating a new
    assessment session.
    """
    return {
        # Fix 1: target_model — correct field name matching PurpleAgentState
        "target_model":         target,
        "attacker_model":       attacker_model,
        "judge_model":          judge_model,
        # Fix 2: target_profile omitted — default_factory builds a clean TargetProfile
        "vector_queue":         [],
        "active_vector":        None,
        "conversation_history": [],
        "findings":             [],
        "remediations":         [],
        "retest_results":       [],
        "phase":                "initialized",
        "phase_history":        [],
        "retry_count":          0,
        "validation_passed":    True,
        # Fix 4: validation_reason removed — field does not exist in PurpleAgentState
        "report_markdown":      "",
    }