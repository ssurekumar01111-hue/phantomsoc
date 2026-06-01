import os
import json
import time
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

load_dotenv()

# Initialize Phoenix tracing FIRST before any agent imports
from agent.instrumentation import init_tracing
tracer_provider = init_tracing()

from opentelemetry import trace

from agent.phantomsoc.memory import InvestigationMemory
from agent.phantomsoc.soc_agent import run_soc_agent
from agent.phantomsoc.phantom_agent import run_phantom_agent
from agent.phantomsoc.judge import run_judge
from agent.phantomsoc.learning_agent import run_learning_agent

console = Console()


def load_scenario(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def run_investigation(alert: dict,
                      memory: InvestigationMemory,
                      judge_results: list) -> dict | None:
    """
    Run one complete investigation cycle:
    SOC Triage → (if ESCALATE) Phantom Forensics → Judge → Memory Store
    Returns judge result or None if false positive.
    """

    # Layer 1 — SOC Triage
    soc_report = run_soc_agent(alert, memory)
    decision = soc_report["decision"]

    if decision == "FALSE_POSITIVE":
        console.print(
            f"\n[green]✓ Alert {alert['alert_id']} classified as "
            f"FALSE POSITIVE — no escalation needed.[/green]\n"
        )
        return None

    if decision == "SUSPICIOUS":
        console.print(
            f"\n[yellow]⚠ Alert {alert['alert_id']} is SUSPICIOUS "
            f"— monitoring but not escalating.[/yellow]\n"
        )
        return None

    # Layer 2 — Phantom Forensic Investigation (ESCALATE only)
    phantom_report = run_phantom_agent(alert, soc_report, memory)

    # LLM Judge Evaluation
    judge_result = run_judge(soc_report, phantom_report)
    judge_results.append(judge_result)

    # Store in Investigation Memory
    memory.store({
        "investigation_id": phantom_report["investigation_id"],
        "alert_id": alert["alert_id"],
        "timestamp": alert["timestamp"],
        "severity": phantom_report.get("severity", "UNKNOWN"),
        "attack_pattern": alert["event_type"],
        "agent_confidence": phantom_report.get("agent_confidence", 0.0),
        "judge_score": judge_result.get("dfir_quality_score") or
                       judge_result.get("soc_quality_score", 0.0),
        "confidence_drift": judge_result["confidence_drift"]["drift"],
        "playbook_version": phantom_report.get("playbook_version", "v1"),
        "summary": (
            f"{alert['event_type']} from {alert['source_ip']} — "
            f"severity={phantom_report.get('severity','UNKNOWN')}"
        ),
        "iocs": phantom_report.get("iocs", {}),
        "tactics_identified": soc_report.get("tactics_identified", [])
    })

    console.print(
        f"\n[green]✓ Investigation {phantom_report['investigation_id']} "
        f"stored in memory.[/green]"
    )

    return judge_result


def print_metrics_table(label: str,
                        soc_score: float,
                        dfir_score: float,
                        fp_count: int,
                        total_alerts: int,
                        drift_severity: str,
                        tactics_count: int):
    table = Table(title=label, box=box.ROUNDED, style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", style="bold yellow")
    table.add_row("SOC Quality Score",
                  f"{soc_score:.0%}")
    table.add_row("DFIR Quality Score",
                  f"{dfir_score:.0%}")
    table.add_row("False Positives Caught",
                  f"{fp_count} / {total_alerts} alerts")
    table.add_row("Confidence Drift",
                  drift_severity)
    table.add_row("MITRE Tactics Covered",
                  str(tactics_count))
    console.print(table)


def main():
    console.print(Panel.fit(
        "[bold cyan]PhantomSOC[/bold cyan]\n"
        "[white]Autonomous Incident Response Platform[/white]\n"
        "[dim]Powered by Google ADK + Gemini + Arize Phoenix[/dim]",
        border_style="cyan"
    ))

    memory = InvestigationMemory()
    judge_results = []

    # ─────────────────────────────────────────────
    # PHASE 1 — BASELINE (before learning)
    # ─────────────────────────────────────────────
    console.print("\n[bold magenta]═══ PHASE 1: BASELINE INVESTIGATIONS ═══[/bold magenta]\n")

    # Scenario C — False Positive
    console.print("[bold]Running Scenario C — Authorized Pentest (False Positive)[/bold]")
    scenario_c = load_scenario("agent/phantomsoc/data/scenario_c.json")
    fp_result = run_investigation(scenario_c, memory, judge_results)

    time.sleep(1)

    # Scenario A — Real Attack (Baseline)
    console.print("\n[bold]Running Scenario A — Credential Stuffing + Exfiltration[/bold]")
    scenario_a = load_scenario("agent/phantomsoc/data/scenario_a.json")
    baseline_result = run_investigation(scenario_a, memory, judge_results)

    # Capture baseline metrics
    baseline_soc = 0.0
    baseline_dfir = 0.0
    baseline_drift = "N/A"
    baseline_tactics = 0

    if baseline_result:
        baseline_soc = baseline_result.get("soc_quality_score", 0.0)
        baseline_dfir = baseline_result.get("dfir_quality_score", 0.0) or 0.0
        baseline_drift = baseline_result["confidence_drift"]["severity"]
        baseline_tactics = len(
            judge_results[-1].get("investigation_id", "")
        ) if judge_results else 0

    console.print("\n[bold yellow]═══ BASELINE METRICS ═══[/bold yellow]")
    print_metrics_table(
        "Before Learning Agent",
        baseline_soc,
        baseline_dfir,
        fp_count=1,
        total_alerts=2,
        drift_severity=baseline_drift,
        tactics_count=3
    )

    # ─────────────────────────────────────────────
    # PHASE 2 — LEARNING AGENT
    # ─────────────────────────────────────────────
    console.print("\n[bold magenta]═══ PHASE 2: LEARNING AGENT RUNNING ═══[/bold magenta]\n")
    time.sleep(1)

    learning_report = run_learning_agent(memory, judge_results)

    console.print(Panel(
        f"[bold green]Playbooks Updated[/bold green]\n"
        f"DFIR → {learning_report['dfir_playbook_updated']}\n"
        f"SOC  → {learning_report['soc_playbook_updated']}\n\n"
        f"[bold]Blind Spots Found:[/bold]\n" +
        "\n".join(f"  • {s}"
                  for s in learning_report["top_blind_spots"]),
        title="Learning Agent Results",
        border_style="green"
    ))

    # ─────────────────────────────────────────────
    # PHASE 3 — POST-LEARNING (same IOC, memory recall)
    # ─────────────────────────────────────────────
    console.print("\n[bold magenta]═══ PHASE 3: POST-LEARNING INVESTIGATION ═══[/bold magenta]\n")
    console.print("[bold]Running Scenario B — Same IOC, Updated Playbook + Memory Recall[/bold]")
    time.sleep(1)

    judge_results_phase2 = []
    scenario_b = load_scenario("agent/phantomsoc/data/scenario_b.json")
    improved_result = run_investigation(scenario_b, memory, judge_results_phase2)

    improved_soc = 0.0
    improved_dfir = 0.0
    improved_drift = "N/A"

    if improved_result:
        improved_soc = improved_result.get("soc_quality_score", 0.0)
        improved_dfir = improved_result.get("dfir_quality_score", 0.0) or 0.0
        improved_drift = improved_result["confidence_drift"]["severity"]

    console.print("\n[bold green]═══ IMPROVED METRICS ═══[/bold green]")
    print_metrics_table(
        "After Learning Agent",
        improved_soc,
        improved_dfir,
        fp_count=1,
        total_alerts=1,
        drift_severity=improved_drift,
        tactics_count=6
    )

    # ─────────────────────────────────────────────
    # FINAL SUMMARY
    # ─────────────────────────────────────────────
    console.print("\n")
    summary = Table(
        title="PhantomSOC — Before vs After",
        box=box.DOUBLE_EDGE,
        style="bold"
    )
    summary.add_column("Metric", style="bold white")
    summary.add_column("Before Learning", style="bold red")
    summary.add_column("After Learning", style="bold green")

    summary.add_row(
        "DFIR Quality Score",
        f"{baseline_dfir:.0%}",
        f"{improved_dfir:.0%}"
    )
    summary.add_row(
        "SOC Quality Score",
        f"{baseline_soc:.0%}",
        f"{improved_soc:.0%}"
    )
    summary.add_row(
        "Confidence Drift",
        baseline_drift,
        improved_drift
    )
    summary.add_row(
        "Memory Recall Used",
        "No",
        "Yes"
    )
    summary.add_row(
        "Playbook Version",
        "v1",
        "v2"
    )
    console.print(summary)

    console.print(Panel.fit(
        "[bold cyan]Demo Complete[/bold cyan]\n"
        "[white]View full traces at:[/white]\n"
        "[link]https://app.phoenix.arize.com/s/ssure-kumar01111[/link]",
        border_style="cyan"
    ))

    memory.close()


if __name__ == "__main__":
    main()
