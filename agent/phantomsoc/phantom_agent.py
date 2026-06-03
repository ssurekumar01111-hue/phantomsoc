import os
import json
import uuid
from datetime import datetime
from dotenv import load_dotenv
from agent.phantomsoc.memory import InvestigationMemory

load_dotenv()


def load_playbook(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def get_latest_dfir_playbook() -> tuple[dict, str]:
    """Load the highest-versioned dfir playbook available."""
    import glob
    files = sorted(glob.glob("playbooks/dfir_v*.json"), reverse=True)
    path = files[0] if files else "playbooks/dfir_v1.json"
    return load_playbook(path), path


def run_phantom_agent(alert: dict,
                      soc_report: dict,
                      memory: InvestigationMemory) -> dict:
    """
    Layer 2 — Phantom Forensic Investigation Agent.
    Returns full investigation report dict.
    """
    print("\n" + "="*60)
    print("LAYER 2 — PHANTOM FORENSIC INVESTIGATION AGENT")
    print("="*60)

    investigation_id = f"INV-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
    print(f"[Phantom] Investigation ID : {investigation_id}")
    print(f"[Phantom] Alert ID         : {alert['alert_id']}")
    print(f"[Phantom] Escalation Reason: {soc_report.get('escalation_reason', 'N/A')}")

    # Step 1 — Load DFIR playbook
    playbook, playbook_path = get_latest_dfir_playbook()
    print(f"\n[Phantom] Loaded playbook  : {playbook_path}")

    # Step 2 — Query investigation memory for related cases
    print("\n[Phantom] Querying investigation memory...")
    related_cases = memory.get_related_cases(
        iocs=[alert["source_ip"]],
        attack_pattern=alert["event_type"],
        limit=5
    )
    memory_context = ""
    if related_cases:
        print(f"[Phantom] ⚠ Found {len(related_cases)} related past case(s):")
        for c in related_cases:
            print(f"          → {c['id']} | {c['severity']} | "
                  f"pattern={c['attack_pattern']}")
            memory_context += (
                f"Related case {c['id']}: severity={c['severity']}, "
                f"attack_pattern={c['attack_pattern']}, "
                f"summary={c['summary']}\n"
            )
    else:
        print("[Phantom] No related cases in memory")

    # Step 3 — Build checklist from playbook
    checklist = "\n".join([
        f"- [{item['category'].upper()}] {item['note']} "
        f"(priority={item['priority']}, required={item['required']})"
        for item in playbook["checklist"]
    ])

    raw_logs = "\n".join(alert["raw_logs"])

    # Step 4 — Forensic investigation prompt
    prompt = f"""You are a Tier-2 DFIR (Digital Forensics and Incident Response) investigator.
Perform a complete forensic investigation of this escalated security incident.

ALERT DETAILS:
- Investigation ID: {investigation_id}
- Alert ID: {alert['alert_id']}
- Timestamp: {alert['timestamp']}
- Source IP: {alert['source_ip']}
- Destination: {alert['destination']}
- Event Type: {alert['event_type']}
- Country: {alert['geolocation']['country']}
- ASN: {alert['geolocation']['asn']}
- Username: {alert['user_context']['username']}

RAW LOGS:
{raw_logs}

SOC TRIAGE FINDINGS:
- Threat Score: {soc_report['threat_score']}/100
- Tactics Identified: {soc_report.get('tactics_identified', [])}
- Escalation Reason: {soc_report.get('escalation_reason', '')}

PAST INVESTIGATION MEMORY:
{memory_context if memory_context else "No related prior cases found."}

DFIR INVESTIGATION CHECKLIST — complete ALL required items:
{checklist}

Perform your investigation and respond ONLY with a JSON object:
{{
  "investigation_id": "{investigation_id}",
  "alert_id": "{alert['alert_id']}",
  "agent_confidence": 0.88,
  "playbook_version": "dfir_v{playbook['version']}",
  "memory_references": [],
  "timeline": [
    {{"time": "HH:MM:SS", "event": "Description of event"}}
  ],
  "iocs": {{
    "ips": [],
    "domains": [],
    "hashes": [],
    "techniques": ["T1110", "T1059.001"]
  }},
  "attack_chain": "Initial Access → Execution → Collection → Exfiltration",
  "persistence_found": false,
  "lateral_movement_found": false,
  "exfiltration": {{
    "confirmed": true,
    "volume": "800MB",
    "records": 50000
  }},
  "severity": "CRITICAL"
}}"""

    # Step 5 — Call Gemini for forensic investigation
    print("\n[Phantom] Running forensic investigation via Gemini...")
    from google import genai
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    response = client.models.generate_content(
        model=model_name,
        contents=prompt
    )
    raw = response.text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    report = json.loads(raw.strip())

    # Step 6 — Print investigation findings
    print(f"\n[Phantom] Timeline ({len(report.get('timeline', []))} events):")
    for event in report.get("timeline", []):
        print(f"          {event['time']} — {event['event']}")

    print(f"\n[Phantom] IOCs Extracted:")
    iocs = report.get("iocs", {})
    print(f"          IPs        : {iocs.get('ips', [])}")
    print(f"          Techniques : {iocs.get('techniques', [])}")

    print(f"\n[Phantom] Attack Chain : {report.get('attack_chain', 'N/A')}")
    print(f"[Phantom] Persistence  : {report.get('persistence_found', False)}")
    print(f"[Phantom] Lateral Mvmt : {report.get('lateral_movement_found', False)}")
    print(f"[Phantom] Exfiltration : {report.get('exfiltration', {})}")
    print(f"[Phantom] Severity     : {report.get('severity', 'N/A')}")
    print(f"[Phantom] Confidence   : {report.get('agent_confidence', 'N/A')}")

    # Step 7 — Generate executive report
    print("\n[Phantom] Generating executive report...")
    exec_prompt = f"""You are a CISO briefing writer.
Write a concise executive incident summary based on this investigation.

INVESTIGATION FINDINGS:
{json.dumps(report, indent=2)}

Write a plain-text executive summary with these sections:
SEVERITY: (one word)
IMPACT: (what was affected, how many records/systems)
ROOT CAUSE: (2 sentences max)
ATTACK SUMMARY: (3-4 sentences, non-technical language)
CONTEXT FROM PAST CASES: (reference memory if relevant, else "No prior cases")
RECOMMENDED ACTIONS: (numbered list, 4-5 items)

Keep it under 250 words. Write for a non-technical executive audience."""

    exec_response = client.models.generate_content(
        model=model_name,
        contents=exec_prompt
    )
    executive_report = exec_response.text.strip()

    print("\n" + "-"*60)
    print("EXECUTIVE SUMMARY")
    print("-"*60)
    print(executive_report)
    print("-"*60)

    # Step 8 — Save executive report
    from agent.core.storage import save_report
    report_url = save_report(investigation_id, executive_report)
    print(f"\n[Phantom] Executive report saved → {report_url}")

    # Step 9 — Add memory references from related cases
    report["memory_references"] = [c["id"] for c in related_cases]
    report["executive_report"] = executive_report

    # Calculate breach risk and cost impact
    print("\n[Phantom] Calculating breach risk and financial impact...")
    from agent.phantomsoc.impact import (
        calculate_breach_risk,
        calculate_cost_impact,
        generate_stakeholder_reports
    )

    breach_risk = calculate_breach_risk(report)

    # Cost impact based on this session (estimated)
    cost_impact = calculate_cost_impact(
        total_alerts=47,
        fp_count=1,
        real_count=2
    )

    print(f"[Phantom] Risk Score       : {breach_risk['risk_score']}/100 — {breach_risk['likelihood']}")
    print(f"[Phantom] Financial Exposure: ${breach_risk['estimated_breach_cost_usd']:,}")
    print(f"[Phantom] Affected Records  : {breach_risk['affected_records']:,}")
    print(f"[Phantom] GDPR Required     : {breach_risk['gdpr_72hr_deadline']}")
    print(f"[Phantom] Analyst Hours Saved: {cost_impact['analyst_hours_saved']}h")
    print(f"[Phantom] Cost Saved        : ${cost_impact['cost_saved_usd']}")

    # Generate multi-stakeholder reports
    print("\n[Phantom] Generating stakeholder reports...")
    try:
        stakeholder_reports = generate_stakeholder_reports(
            alert, soc_report, report, breach_risk, cost_impact
        )
        print("[Phantom] ✓ SOC Analyst report generated")
        print("[Phantom] ✓ Security Manager report generated")
        print("[Phantom] ✓ Executive briefing generated")
        print("[Phantom] ✓ Compliance report generated")
    except Exception as e:
        print(f"[Phantom] Warning: stakeholder reports failed: {e}")
        stakeholder_reports = {}

    # Generate autonomous runbook
    print("\n[Phantom] Generating autonomous runbook...")
    try:
        from agent.phantomsoc.runbook import (
            generate_runbook,
            save_runbook_to_gcs
        )
        runbook = generate_runbook(
            alert, report, breach_risk
        )
        gcs_path = save_runbook_to_gcs(runbook)
        report["runbook"] = runbook
        report["runbook_gcs_path"] = gcs_path
        phases = list(runbook.get("phases", {}).keys())
        print(f"[Phantom] ✓ Runbook generated: "
              f"{runbook.get('runbook_id')}")
        print(f"[Phantom] ✓ Phases: "
              f"{', '.join(phases)}")
        print(f"[Phantom] ✓ Saved to GCS: {gcs_path}")
    except Exception as e:
        print(f"[Phantom] Warning: runbook generation "
              f"failed: {e}")
        report["runbook"] = {}
        report["runbook_gcs_path"] = ""

    # Add to report
    report["breach_risk"] = breach_risk
    report["cost_impact"] = cost_impact
    report["stakeholder_reports"] = stakeholder_reports

    # Append breach risk to executive report
    risk_summary = f"""
--- BREACH RISK ASSESSMENT ---
Risk Score: {breach_risk['risk_score']}/100 ({breach_risk['likelihood']})
Estimated Financial Exposure: ${breach_risk['estimated_breach_cost_usd']:,}
Affected Records: {breach_risk['affected_records']:,}
GDPR 72-Hour Notification: {'REQUIRED' if breach_risk['gdpr_72hr_deadline'] else 'Not required'}
Analyst Hours Saved by PhantomSOC: {cost_impact['analyst_hours_saved']}h
Cost Saved: ${cost_impact['cost_saved_usd']}
"""
    report_path = f"reports/executive/{investigation_id}.txt"
    with open(report_path, "a") as f:
        f.write(risk_summary)

    return report
