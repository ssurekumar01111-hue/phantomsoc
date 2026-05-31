import os
import json
import glob
from dotenv import load_dotenv
import google.generativeai as genai
from agent.phantomsoc.memory import InvestigationMemory

load_dotenv()
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))


def get_next_playbook_version(prefix: str) -> tuple[int, str]:
    files = glob.glob(f"playbooks/{prefix}_v*.json")
    versions = []
    for f in files:
        try:
            v = int(f.split("_v")[1].replace(".json", ""))
            versions.append(v)
        except (IndexError, ValueError):
            pass
    next_v = max(versions) + 1 if versions else 2
    return next_v, f"playbooks/{prefix}_v{next_v}.json"


def query_phoenix_mcp_summary(judge_results: list[dict]) -> str:
    """
    Builds a Phoenix MCP query summary from available judge data.
    In production this queries Phoenix MCP server directly.
    For the hackathon demo this formats trace data that was
    sent to Phoenix for the MCP server to serve back.
    Returns a formatted string for the Learning Agent prompt.
    """
    if not judge_results:
        return "No Phoenix trace data available yet."

    lines = ["Phoenix Trace Analysis Summary:"]
    lines.append(f"Total investigations traced: {len(judge_results)}")

    low_soc = [r for r in judge_results
               if r.get("soc_quality_score", 1.0) < 0.65]
    low_dfir = [r for r in judge_results
                if (r.get("dfir_quality_score") or 1.0) < 0.70]
    critical = [r for r in judge_results
                if r.get("confidence_drift", {}).get(
                    "severity") == "CRITICAL"]

    lines.append(
        f"Investigations with SOC score below 65%: {len(low_soc)}"
    )
    lines.append(
        f"Investigations with DFIR score below 70%: {len(low_dfir)}"
    )
    lines.append(
        f"Critical confidence drift events: {len(critical)}"
    )

    if low_soc:
        lines.append("SOC feedback from low-scoring traces:")
        for r in low_soc:
            lines.append(f"  - {r.get('soc_feedback', 'N/A')}")

    if low_dfir:
        lines.append("DFIR feedback from low-scoring traces:")
        for r in low_dfir:
            lines.append(f"  - {r.get('dfir_feedback', 'N/A')}")

    lines.append(
        "Phoenix MCP URL: "
        "https://app.phoenix.arize.com/s/ssure-kumar01111"
    )
    return "\n".join(lines)


def run_learning_agent(memory: InvestigationMemory,
                       judge_results: list[dict]) -> dict:
    """
    Layer 3 — Learning Meta-Agent.
    Analyzes past judge scores and drift events.
    Rewrites SOC and DFIR playbooks.
    """
    print("\n" + "="*60)
    print("LAYER 3 — LEARNING META-AGENT")
    print("="*60)

    # Step 1 — Gather data from memory
    drift_history = memory.get_drift_history(last_n=10)
    critical_drifts = [
        d for d in drift_history
        if d.get("severity") in ("CRITICAL", "WARNING")
    ]

    print(f"[Learning] Cases analyzed       : {len(judge_results)}")
    print(f"[Learning] Drift events (WARNING+): {len(critical_drifts)}")

    # Step 2 — Compute averages
    soc_scores = [r["soc_quality_score"] for r in judge_results
                  if r.get("soc_quality_score") is not None]
    dfir_scores = [r["dfir_quality_score"] for r in judge_results
                   if r.get("dfir_quality_score") is not None]
    avg_soc = round(sum(soc_scores) / len(soc_scores), 3) if soc_scores else 0
    avg_dfir = round(sum(dfir_scores) / len(dfir_scores), 3) if dfir_scores else 0

    print(f"[Learning] Avg SOC score        : {avg_soc:.2f}")
    print(f"[Learning] Avg DFIR score       : {avg_dfir:.2f}")

    # Step 3 — Load current playbooks
    soc_files = sorted(glob.glob("playbooks/soc_rules_v*.json"), reverse=True)
    dfir_files = sorted(glob.glob("playbooks/dfir_v*.json"), reverse=True)
    current_soc = json.load(open(soc_files[0])) if soc_files else {}
    current_dfir = json.load(open(dfir_files[0])) if dfir_files else {}

    # Step 4 — Collect all feedback
    all_feedback = "\n".join([
        f"Case {r.get('investigation_id', 'N/A')}: "
        f"SOC={r.get('soc_quality_score', 0):.2f}, "
        f"DFIR={r.get('dfir_quality_score', 'N/A')}, "
        f"SOC feedback: {r.get('soc_feedback', '')}, "
        f"DFIR feedback: {r.get('dfir_feedback', '')}"
        for r in judge_results
    ])

    drift_summary = "\n".join([
        f"Case {d['id']}: confidence={d['agent_confidence']:.2f}, "
        f"judge={d['judge_score']:.2f}, drift={d['drift']:+.3f}, "
        f"severity={d['severity']}"
        for d in critical_drifts
    ]) if critical_drifts else "No critical drift events detected."

    # Step 5 — Ask Gemini to analyze and improve playbooks
    print("\n[Learning] Analyzing investigation blind spots...")
    model = genai.GenerativeModel(
        os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    )

    analysis_prompt = f"""You are an AI security operations researcher.
Analyze this set of investigation quality scores and feedback.
Identify systematic blind spots and generate improved playbooks.

INVESTIGATION QUALITY SCORES (from Phoenix traces):
{query_phoenix_mcp_summary(judge_results)}

RAW FEEDBACK DETAILS:
{all_feedback}

CONFIDENCE DRIFT EVENTS:
{drift_summary}

CURRENT SOC RULES:
{json.dumps(current_soc, indent=2)}

CURRENT DFIR CHECKLIST:
{json.dumps(current_dfir, indent=2)}

Based on the feedback patterns, identify:
1. What categories are consistently scoring poorly?
2. What steps are being skipped or done poorly?
3. What confidence drift patterns exist?

Then generate improved versions of both playbooks.

Respond ONLY with JSON:
{{
  "analysis": {{
    "top_blind_spots": [
      "Specific blind spot 1",
      "Specific blind spot 2"
    ],
    "drift_pattern": "Description of overconfidence pattern if any",
    "root_cause": "Why are scores low?"
  }},
  "soc_improvements": [
    "Specific change 1 to SOC rules",
    "Specific change 2 to SOC rules"
  ],
  "dfir_improvements": [
    "Specific change 1 to DFIR checklist",
    "Specific change 2 to DFIR checklist"
  ],
  "updated_dfir_checklist": [
    {{
      "category": "timeline",
      "required": true,
      "priority": 1,
      "note": "Updated note"
    }}
  ]
}}"""

    response = model.generate_content(analysis_prompt)
    raw = response.text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    analysis = json.loads(raw.strip())

    # Step 6 — Print findings
    print("\n[Learning] ═══ BLIND SPOTS IDENTIFIED ═══")
    for spot in analysis["analysis"]["top_blind_spots"]:
        print(f"           ● {spot}")
    print(f"\n[Learning] Root Cause: {analysis['analysis']['root_cause']}")
    if analysis["analysis"].get("drift_pattern"):
        print(f"[Learning] Drift Pattern: {analysis['analysis']['drift_pattern']}")

    # Step 7 — Write updated DFIR playbook
    dfir_v, dfir_path = get_next_playbook_version("dfir")
    new_dfir = {
        "version": dfir_v,
        "description": f"Updated by Learning Agent — v{dfir_v}",
        "generated_by": "learning_agent",
        "trigger_reason": analysis["analysis"]["root_cause"],
        "improvements": analysis["dfir_improvements"],
        "checklist": analysis.get(
            "updated_dfir_checklist",
            current_dfir.get("checklist", [])
        )
    }
    with open(dfir_path, "w") as f:
        json.dump(new_dfir, f, indent=2)
    print(f"\n[Learning] ✓ DFIR playbook updated → {dfir_path}")
    print(f"           Changes:")
    for change in analysis["dfir_improvements"]:
        print(f"           + {change}")

    # Step 8 — Write updated SOC playbook
    soc_v, soc_path = get_next_playbook_version("soc_rules")
    new_soc = dict(current_soc)
    new_soc["version"] = soc_v
    new_soc["generated_by"] = "learning_agent"
    new_soc["improvements"] = analysis["soc_improvements"]
    with open(soc_path, "w") as f:
        json.dump(new_soc, f, indent=2)
    print(f"\n[Learning] ✓ SOC rules updated → {soc_path}")
    print(f"           Changes:")
    for change in analysis["soc_improvements"]:
        print(f"           + {change}")

    return {
        "cases_analyzed": len(judge_results),
        "avg_soc_score": avg_soc,
        "avg_dfir_score": avg_dfir,
        "critical_drift_events": len(critical_drifts),
        "top_blind_spots": analysis["analysis"]["top_blind_spots"],
        "root_cause": analysis["analysis"]["root_cause"],
        "dfir_playbook_updated": dfir_path,
        "soc_playbook_updated": soc_path
    }
