"""
ollama-purple-agent — CLI entry point.

Commands:
    run       — Execute a full purple-team assessment pipeline
    dashboard — Launch the Streamlit real-time monitoring dashboard
    diagram   — Print the LangGraph state machine topology

Usage:
    python -m src.main run
    python -m src.main run --target llama3.1:8b --phase enumeration
    python -m src.main dashboard
    python -m src.main diagram

Security Reason: The CLI is the only public interface to the graph.
All model selection defaults to config.py — no credentials or keys
are accepted as CLI arguments to prevent shell history exposure.
"""

from __future__ import annotations

import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

import click
import structlog

from src.config import config
from src.graph.orchestrator import build_purple_graph, create_initial_state

# ────────────────────────────────────────────────────────────────────────
# Logging setup
# ────────────────────────────────────────────────────────────────────────

import logging as _stdlib_logging
_stdlib_logging.basicConfig(
    level=_stdlib_logging.INFO,
    format="%(levelname)s [%(name)s] %(message)s",
)

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.dev.ConsoleRenderer(colors=True),
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger("purple_team.main")

# ────────────────────────────────────────────────────────────────────────
# Output paths
# ────────────────────────────────────────────────────────────────────────

OUTPUT_DIR = Path("output/reports")

VALID_PHASES = [
    "recon",
    "enumeration",
    "attack",
]

# ────────────────────────────────────────────────────────────────────────
# ASCII diagram (mirrors orchestrator.py docstring topology)
# ────────────────────────────────────────────────────────────────────────

DIAGRAM = """
ollama-purple-agent — State Machine Topology
═══════════════════════════════════════════════════════════

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

Scoring Rubric:
    0 = Held          → Informational
    1 = Partial       → Medium
    2 = Soft Bypass   → High
    3 = Full Bypass   → Critical

═══════════════════════════════════════════════════════════
"""


# ────────────────────────────────────────────────────────────────────────
# CLI group
# ────────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """
    ollama-purple-agent — Autonomous LLM Purple Team Assessment System.

    Runs entirely against locally-hosted Ollama models.
    Does not connect to or target any live AI systems.
    """
    pass


# ────────────────────────────────────────────────────────────────────────
# run command
# ────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--target",
    default=config.TARGET_MODEL,
    show_default=True,
    help="Ollama model name for the Target (shadow assistant) agent.",
)
@click.option(
    "--attacker",
    default=config.ATTACKER_MODEL,
    show_default=True,
    help="Ollama model name for the Attacker agent.",
)
@click.option(
    "--judge",
    default=config.JUDGE_MODEL,
    show_default=True,
    help="Ollama model name for the Judge agent.",
)
@click.option(
    "--phase",
    default="recon",
    type=click.Choice(VALID_PHASES, case_sensitive=False),
    show_default=True,
    help="Phase to begin the assessment from.",
)
@click.option(
    "--output-dir",
    default=str(OUTPUT_DIR),
    show_default=True,
    help="Directory to save the assessment report.",
)
def run(target: str, attacker: str, judge: str, phase: str, output_dir: str):
    """
    Execute a full purple-team assessment pipeline.

    All models default to values defined in config.py / .env.
    Override individually with --target, --attacker, or --judge.

    Security Reason: No API keys or credentials are accepted as CLI
    arguments. All sensitive config is loaded from the environment
    via config.py to prevent shell history exposure.
    """
    click.echo("")
    click.echo(click.style("  ollama-purple-agent", fg="magenta", bold=True))
    click.echo(click.style("  Autonomous LLM Purple Team Assessment", fg="white"))
    click.echo("")
    click.echo(f"  Target   : {click.style(target, fg='cyan')}")
    click.echo(f"  Attacker : {click.style(attacker, fg='yellow')}")
    click.echo(f"  Judge    : {click.style(judge, fg='green')}")
    click.echo(f"  Start    : {click.style(phase, fg='white')}")
    click.echo("")

    # Confirm before firing
    if not click.confirm(
        click.style("  Launch assessment?", fg="yellow"), default=True
    ):
        click.echo(click.style("  Aborted.", fg="red"))
        return

    click.echo("")
    logger.info("run: building graph")

    try:
        app = build_purple_graph()
    except Exception as e:
        logger.error("run: graph compilation failed", error=str(e))
        click.echo(click.style(f"\n  ERROR: Graph failed to compile: {e}", fg="red"))
        sys.exit(1)

    initial_state = create_initial_state(
        target=target,
        attacker_model=attacker,
        judge_model=judge,
    )

    # If starting from a non-recon phase, set the phase override
    if phase != "recon":
        initial_state["phase"] = f"{phase}_override"
        logger.info("run: starting from phase override", phase=phase)

    click.echo(click.style("  Running assessment pipeline...\n", fg="white"))

    try:
        final_state = app.invoke(initial_state)
    except KeyboardInterrupt:
        click.echo(click.style("\n\n  Assessment interrupted by user.", fg="yellow"))
        sys.exit(0)
    except Exception as e:
        logger.error("run: pipeline execution failed", error=str(e))
        click.echo(click.style(f"\n  ERROR: Pipeline failed: {e}", fg="red"))
        sys.exit(1)

    # ── Extract report ──
    report_markdown = final_state.get("report_markdown", "")

    if not report_markdown:
        click.echo(click.style("\n  WARNING: No report was generated.", fg="yellow"))
        return

    # ── Print summary to console ──
    findings = final_state.get("findings", [])
    remediations = final_state.get("remediations", [])
    critical = sum(1 for f in findings if f.severity == "Critical" and not f.is_fallback)
    high     = sum(1 for f in findings if f.severity == "High" and not f.is_fallback)
    medium   = sum(1 for f in findings if f.severity == "Medium" and not f.is_fallback)
    fallbacks = sum(1 for f in findings if f.is_fallback)

    click.echo("")
    click.echo(click.style("  ── Assessment Complete ──", fg="magenta", bold=True))
    click.echo("")
    click.echo(f"  Findings   : {click.style(str(len(findings)), fg='white', bold=True)}")
    click.echo(f"  Critical   : {click.style(str(critical), fg='red', bold=True)}")
    click.echo(f"  High       : {click.style(str(high), fg='yellow', bold=True)}")
    click.echo(f"  Medium     : {click.style(str(medium), fg='cyan')}")
    click.echo(f"  Fallbacks  : {click.style(str(fallbacks), fg='white')}")
    click.echo(f"  Patches    : {click.style(str(len(remediations)), fg='green')}")
    click.echo("")

    # ── Auto-save report ──
    report_path = _save_report(
        report_markdown=report_markdown,
        target=target,
        output_dir=output_dir,
    )

    if report_path:
        click.echo(
            click.style(f"  Report saved → ", fg="white") +
            click.style(str(report_path), fg="green", bold=True)
        )
        click.echo("")

        # ── Prompt to open ──
        if click.confirm(
            click.style("  Open report now?", fg="yellow"), default=True
        ):
            _open_report(report_path)
    else:
        click.echo(click.style("  WARNING: Report could not be saved.", fg="yellow"))


# ────────────────────────────────────────────────────────────────────────
# dashboard command
# ────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--port",
    default=8501,
    show_default=True,
    help="Port to run the Streamlit dashboard on.",
)
def dashboard(port: int):
    """
    Launch the Streamlit real-time monitoring dashboard.

    The dashboard provides live phase tracking, findings tables,
    vector queue visibility, and report rendering.
    """
    dashboard_path = Path("src/ui/dashboard.py")

    if not dashboard_path.exists():
        click.echo(click.style(
            f"\n  ERROR: Dashboard not found at {dashboard_path}",
            fg="red"
        ))
        sys.exit(1)

    click.echo("")
    click.echo(click.style("  Launching dashboard...", fg="magenta"))
    click.echo(click.style(f"  → http://localhost:{port}", fg="cyan"))
    click.echo("")

    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run",
            str(dashboard_path),
            "--server.port", str(port),
            "--server.headless", "false",
        ], check=True)
    except FileNotFoundError:
        click.echo(click.style(
            "\n  ERROR: Streamlit not installed. Run: pip install streamlit",
            fg="red"
        ))
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo(click.style("\n  Dashboard stopped.", fg="yellow"))


# ────────────────────────────────────────────────────────────────────────
# diagram command
# ────────────────────────────────────────────────────────────────────────

@cli.command()
def diagram():
    """
    Print the LangGraph state machine topology to the console.
    """
    click.echo(click.style(DIAGRAM, fg="cyan"))


# ────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────

def _save_report(
    report_markdown: str,
    target: str,
    output_dir: str,
) -> Path | None:
    """
    Save the assessment report to disk.

    Filename format: report_<target>_<timestamp>.md
    Creates the output directory if it does not exist.

    Security Reason: Target model name is sanitized before use in the
    filename to prevent path traversal via maliciously crafted model names.
    """
    try:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # Sanitize target name for filesystem safety
        # Dots excluded to prevent path traversal via model names like "../../etc"
        safe_target = "".join(
            c if c.isalnum() or c in ("-", "_") else "_"
            for c in target
        )
        # Collapse runs of underscores and strip leading/trailing ones
        while "__" in safe_target:
            safe_target = safe_target.replace("__", "_")
        safe_target = safe_target.strip("_") or "target"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{safe_target}_{timestamp}.md"
        report_path = out / filename

        report_path.write_text(report_markdown, encoding="utf-8")
        logger.info("report saved", path=str(report_path))
        return report_path

    except Exception as e:
        logger.error("_save_report: failed to save report", error=str(e))
        return None


def _open_report(path: Path) -> None:
    """
    Open the report file using the system's default Markdown viewer.

    Falls back to printing the path if no viewer is available.
    """
    try:
        if sys.platform == "win32":
            os.startfile(str(path))
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=True)
        else:
            subprocess.run(["xdg-open", str(path)], check=True)
    except Exception as e:
        logger.warning("_open_report: could not open file automatically", error=str(e))
        click.echo(click.style(
            f"\n  Could not open automatically. File is at:\n  {path}",
            fg="yellow"
        ))


# ────────────────────────────────────────────────────────────────────────
# Entry point
# ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()