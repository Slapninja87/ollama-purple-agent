"""
Streamlit real-time monitoring dashboard for ollama-purple-agent.

Provides live visibility into:
  - Phase progression
  - Active attack vector
  - Findings table (color-coded by severity)
  - Vector queue status
  - Judge fallback alerts
  - Final report rendering

Launch via:
    python -m src.main dashboard
    # or directly:
    streamlit run src/ui/dashboard.py

Security Reason: The dashboard is read-only. It monitors state produced
by the pipeline but cannot modify it. No credentials or model names
are editable from the dashboard — those are set in config.py / .env.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

# ────────────────────────────────────────────────────────────────────────
# Page config — must be first Streamlit call
# ────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="ollama-purple-agent",
    page_icon="🟣",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical":      "#FF4444",
    "High":          "#FF8C00",
    "Medium":        "#FFD700",
    "Informational": "#888888",
}

SEVERITY_ICONS = {
    "Critical":      "🔴",
    "High":          "🟠",
    "Medium":        "🟡",
    "Informational": "⚪",
}

PHASE_ICONS = {
    "init":                  "⚙️",
    "initialized":           "⚙️",
    "recon_complete":        "🔍",
    "enumeration_complete":  "📋",
    "attack_complete":       "⚔️",
    "attack_exhausted":      "✅",
    "judge_complete":        "⚖️",
    "judge_skipped":         "⏭️",
    "remediate_complete":    "🩹",
    "remediate_skipped":     "⏭️",
    "harden_complete":       "🛡️",
    "harden_skipped":        "⏭️",
    "report_complete":       "📄",
}

REPORT_DIR = Path("output/reports")


# ────────────────────────────────────────────────────────────────────────
# Session state initialization
# ────────────────────────────────────────────────────────────────────────

def init_session_state():
    defaults = {
        "pipeline_running":   False,
        "pipeline_complete":  False,
        "current_phase":      "Not started",
        "phase_history":      [],
        "findings":           [],
        "remediations":       [],
        "retest_results":     [],
        "vector_queue":       [],
        "active_vector":      None,
        "target_profile":     None,
        "report_markdown":    "",
        "fallback_count":     0,
        "last_updated":       None,
        "target_model":       "",
        "attacker_model":     "",
        "judge_model":        "",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


init_session_state()


# ────────────────────────────────────────────────────────────────────────
# CSS
# ────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    /* Main background */
    .stApp { background-color: #0E0E0E; color: #E0E0E0; }

    /* Metric cards */
    [data-testid="metric-container"] {
        background-color: #1A1A1A;
        border: 1px solid #2A2A2A;
        border-radius: 8px;
        padding: 16px;
    }

    /* Severity badges */
    .badge-critical      { background:#FF4444; color:#fff; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:700; }
    .badge-high          { background:#FF8C00; color:#fff; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:700; }
    .badge-medium        { background:#FFD700; color:#000; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:700; }
    .badge-informational { background:#555;    color:#fff; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:700; }

    /* Phase pill */
    .phase-pill {
        background:#1E1E3A; color:#A0A0FF;
        border:1px solid #3A3A7A;
        padding:6px 16px; border-radius:20px;
        font-size:14px; font-weight:600;
        display:inline-block;
    }

    /* Finding card */
    .finding-card {
        background:#1A1A1A; border:1px solid #2A2A2A;
        border-radius:8px; padding:16px; margin-bottom:12px;
    }
    .finding-card-critical      { border-left: 4px solid #FF4444; }
    .finding-card-high          { border-left: 4px solid #FF8C00; }
    .finding-card-medium        { border-left: 4px solid #FFD700; }
    .finding-card-informational { border-left: 4px solid #555555; }

    /* Vector queue item */
    .vector-item {
        background:#111; border:1px solid #222;
        border-radius:6px; padding:8px 12px; margin-bottom:6px;
        font-family: monospace; font-size:12px;
    }

    /* Sidebar */
    [data-testid="stSidebar"] { background-color:#111; }

    /* Section headers */
    .section-header {
        color:#A0A0FF; font-size:13px; font-weight:700;
        letter-spacing:1px; text-transform:uppercase;
        border-bottom:1px solid #2A2A2A; padding-bottom:6px;
        margin-bottom:12px;
    }

    /* Alert box */
    .alert-box {
        background:#2A1A1A; border:1px solid #FF4444;
        border-radius:8px; padding:12px; margin-bottom:12px;
        color:#FF9999;
    }
</style>
""", unsafe_allow_html=True)


# ────────────────────────────────────────────────────────────────────────
# Sidebar
# ────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🟣 purple-agent")
    st.markdown("---")

    # Load config for display
    try:
        from src.config import config as app_config
        st.markdown("**Models**")
        st.code(f"Target:   {app_config.TARGET_MODEL}\nAttacker: {app_config.ATTACKER_MODEL}\nJudge:    {app_config.JUDGE_MODEL}", language=None)
        st.markdown(f"**Cloud Mode:** {'✅ On' if app_config.JUDGE_IS_CLOUD else '❌ Off'}")
    except Exception:
        st.warning("config.py not loaded")

    st.markdown("---")

    # Pipeline controls
    st.markdown("**Pipeline**")

    if st.button(
        "▶ Launch Assessment",
        disabled=st.session_state.pipeline_running,
        use_container_width=True,
        type="primary",
    ):
        st.session_state.pipeline_running = True
        st.session_state.pipeline_complete = False
        st.session_state.findings = []
        st.session_state.remediations = []
        st.session_state.phase_history = []
        st.session_state.report_markdown = ""
        st.session_state.fallback_count = 0
        st.rerun()

    if st.button(
        "⏹ Reset",
        disabled=not st.session_state.pipeline_running and not st.session_state.pipeline_complete,
        use_container_width=True,
    ):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        init_session_state()
        st.rerun()

    st.markdown("---")

    # Load existing report
    st.markdown("**Reports**")
    report_files = sorted(REPORT_DIR.glob("*.md"), reverse=True) if REPORT_DIR.exists() else []
    if report_files:
        selected_report = st.selectbox(
            "Load saved report",
            options=report_files,
            format_func=lambda p: p.name,
        )
        if st.button("Load", use_container_width=True):
            st.session_state.report_markdown = selected_report.read_text(encoding="utf-8")
            st.session_state.pipeline_complete = True
            st.rerun()
    else:
        st.caption("No saved reports found.")

    st.markdown("---")
    if st.session_state.last_updated:
        st.caption(f"Last updated: {st.session_state.last_updated}")


# ────────────────────────────────────────────────────────────────────────
# Main layout
# ────────────────────────────────────────────────────────────────────────

st.markdown("## 🟣 ollama-purple-agent — Assessment Dashboard")
st.markdown("---")

# ── Status bar ──
status_col, phase_col, time_col = st.columns([1, 2, 1])

with status_col:
    if st.session_state.pipeline_running and not st.session_state.pipeline_complete:
        st.markdown("**Status:** 🟡 Running")
    elif st.session_state.pipeline_complete:
        st.markdown("**Status:** 🟢 Complete")
    else:
        st.markdown("**Status:** ⚫ Idle")

with phase_col:
    phase = st.session_state.current_phase
    icon = PHASE_ICONS.get(phase, "🔄")
    st.markdown(
        f"**Current Phase:** <span class='phase-pill'>{icon} {phase}</span>",
        unsafe_allow_html=True
    )

with time_col:
    st.markdown(f"**Time:** {datetime.now().strftime('%H:%M:%S')}")

st.markdown("---")

# ── Metrics row ──
m1, m2, m3, m4, m5, m6 = st.columns(6)

findings = st.session_state.findings
remediations = st.session_state.remediations

critical_count      = sum(1 for f in findings if f.get("severity") == "Critical" and not f.get("is_fallback"))
high_count          = sum(1 for f in findings if f.get("severity") == "High" and not f.get("is_fallback"))
medium_count        = sum(1 for f in findings if f.get("severity") == "Medium" and not f.get("is_fallback"))
fallback_count      = sum(1 for f in findings if f.get("is_fallback"))
bypass_total        = sum(1 for f in findings if f.get("bypass_confirmed") and not f.get("is_fallback"))
remediation_count   = len(remediations)

m1.metric("🔴 Critical",     critical_count)
m2.metric("🟠 High",         high_count)
m3.metric("🟡 Medium",       medium_count)
m4.metric("✅ Bypasses",     bypass_total)
m5.metric("🩹 Patches",      remediation_count)
m6.metric("⚠️ Fallbacks",    fallback_count)

st.markdown("---")

# ── Main content tabs ──
tab_live, tab_findings, tab_queue, tab_profile, tab_report = st.tabs([
    "⚔️ Live Feed",
    "⚖️ Findings",
    "📋 Vector Queue",
    "🔍 Target Profile",
    "📄 Report",
])


# ─────────────────────────────────
# Tab 1: Live Feed
# ─────────────────────────────────
with tab_live:
    st.markdown('<div class="section-header">Active Vector</div>', unsafe_allow_html=True)

    active = st.session_state.active_vector
    if active:
        col_vc, col_gen = st.columns([2, 1])
        col_vc.markdown(f"**Class:** `{active.get('vector_class', 'N/A')}`")
        col_gen.markdown(f"**Generation:** {active.get('mutation_generation', 0)}")
        with st.expander("Payload", expanded=True):
            st.code(active.get("payload", ""), language=None)
    else:
        st.caption("No active vector.")

    st.markdown("---")
    st.markdown('<div class="section-header">Phase History</div>', unsafe_allow_html=True)

    phase_history = st.session_state.phase_history
    if phase_history:
        phase_str = " → ".join(
            f"{PHASE_ICONS.get(p, '🔄')} {p}" for p in phase_history[-10:]
        )
        st.markdown(phase_str)
        if len(phase_history) > 10:
            st.caption(f"... and {len(phase_history) - 10} earlier phases")
    else:
        st.caption("Pipeline not started.")

    # Fallback alert
    if fallback_count > 0:
        st.markdown("---")
        st.markdown(
            f'<div class="alert-box">⚠️ <strong>{fallback_count} Judge fallback(s)</strong> detected. '
            f'The Judge model produced invalid output — these findings were auto-flagged and excluded from severity counts.</div>',
            unsafe_allow_html=True
        )

    # Auto-refresh while running
    if st.session_state.pipeline_running and not st.session_state.pipeline_complete:
        time.sleep(2)
        st.rerun()


# ─────────────────────────────────
# Tab 2: Findings
# ─────────────────────────────────
with tab_findings:
    st.markdown('<div class="section-header">Findings by Severity</div>', unsafe_allow_html=True)

    if not findings:
        st.caption("No findings yet.")
    else:
        for severity in ["Critical", "High", "Medium", "Informational"]:
            sev_findings = [
                f for f in findings
                if f.get("severity") == severity and not f.get("is_fallback")
            ]
            if not sev_findings:
                continue

            color = SEVERITY_COLORS[severity]
            icon  = SEVERITY_ICONS[severity]
            st.markdown(f"#### {icon} {severity} ({len(sev_findings)})")

            for i, f in enumerate(sev_findings, 1):
                with st.expander(
                    f"{icon} [{severity}] {f.get('vector', {}).get('vector_class', 'Unknown')} — Finding {i}",
                    expanded=(severity == "Critical"),
                ):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Score", f"{f.get('score', 0)}/3")
                    c2.metric("Bypass", "Yes" if f.get("bypass_confirmed") else "No")
                    c3.metric("Generation", f.get("vector", {}).get("mutation_generation", 0))

                    st.markdown("**Judge Reasoning:**")
                    st.info(f.get("judge_reasoning", "N/A"))

                    payload = f.get("vector", {}).get("payload", "")
                    if payload:
                        with st.expander("Payload"):
                            st.code(payload[:500] + ("..." if len(payload) > 500 else ""), language=None)

                    response = f.get("response", "")
                    if response:
                        with st.expander("Target Response"):
                            st.code(response[:500] + ("..." if len(response) > 500 else ""), language=None)

        # Fallback findings section
        fallback_findings = [f for f in findings if f.get("is_fallback")]
        if fallback_findings:
            st.markdown("#### ⚠️ Fallback Records (Judge Errors)")
            for f in fallback_findings:
                with st.expander(
                    f"⚠️ Fallback — {f.get('vector', {}).get('vector_class', 'Unknown')}"
                ):
                    st.warning(f.get("judge_reasoning", "N/A"))


# ─────────────────────────────────
# Tab 3: Vector Queue
# ─────────────────────────────────
with tab_queue:
    st.markdown('<div class="section-header">Remaining Attack Queue</div>', unsafe_allow_html=True)

    queue = st.session_state.vector_queue
    if not queue:
        if st.session_state.pipeline_complete:
            st.success("All vectors exhausted — assessment complete.")
        else:
            st.caption("Queue is empty or not yet populated.")
    else:
        st.markdown(f"**{len(queue)} vector(s) remaining**")
        for i, v in enumerate(queue, 1):
            vc   = v.get("vector_class", "Unknown")
            gen  = v.get("mutation_generation", 0)
            st.markdown(
                f'<div class="vector-item">'
                f'<strong>{i}.</strong> {vc} '
                f'<span style="color:#666; float:right">gen {gen}</span>'
                f'</div>',
                unsafe_allow_html=True
            )


# ─────────────────────────────────
# Tab 4: Target Profile
# ─────────────────────────────────
with tab_profile:
    st.markdown('<div class="section-header">Recon Intelligence</div>', unsafe_allow_html=True)

    profile = st.session_state.target_profile
    if not profile:
        st.caption("Recon has not completed yet.")
    else:
        col_a, col_b = st.columns(2)

        col_a.markdown("**Model Name**")
        col_a.code(profile.get("model_name", "Unknown"))

        col_b.markdown("**Refusal Style**")
        col_b.code(profile.get("refusal_style", "unknown"))

        st.markdown("**Persona**")
        st.info(profile.get("persona", "Not detected") or "Not detected")

        guardrails = profile.get("detected_guardrail_categories", [])
        st.markdown(f"**Detected Guardrail Categories** ({len(guardrails)})")
        if guardrails:
            for g in guardrails:
                st.markdown(f"- `{g}`")
        else:
            st.caption("None detected.")

        hints = profile.get("system_prompt_hints", [])
        if hints:
            st.markdown(f"**System Prompt Hints** ({len(hints)})")
            for h in hints:
                st.markdown(f"- {h}")


# ─────────────────────────────────
# Tab 5: Report
# ─────────────────────────────────
with tab_report:
    st.markdown('<div class="section-header">Assessment Report</div>', unsafe_allow_html=True)

    report_md = st.session_state.report_markdown

    if not report_md:
        st.caption("Report will appear here when the pipeline completes.")
    else:
        # Download button
        target_name = st.session_state.target_model or "target"
        safe_target = "".join(
            c if c.isalnum() or c in ("-", "_", ".") else "_"
            for c in target_name
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{safe_target}_{timestamp}.md"

        st.download_button(
            label="⬇️ Download Report",
            data=report_md,
            file_name=filename,
            mime="text/markdown",
            use_container_width=True,
        )

        st.markdown("---")
        st.markdown(report_md)