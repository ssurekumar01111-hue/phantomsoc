import os
import json
from dotenv import load_dotenv
from agent.phantomsoc.memory import InvestigationMemory

load_dotenv()


def load_playbook(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def run_soc_agent(alert: dict,
                  memory: InvestigationMemory) -> dict:
    """
    Layer 1 — SOC Triage Agent.
    Returns a SOC triage report dict.
    """
    print("\n" + "="*60)
    print("LAYER 1 — SOC TRIAGE AGENT")
    print("="*60)
    print(f"[SOC] Alert ID      : {alert.get('alert_id', 'Unknown')}")
    print(f"[SOC] Source IP     : {alert.get('source_ip', 'Unknown')}")
    print(f"[SOC] Event Type    : {alert.get('event_type', 'Unknown')}")
    print(f"[SOC] Country/ASN   : "
          f"{alert.get('geolocation', {}).get('country', 'Unknown')} / "
          f"{alert.get('geolocation', {}).get('asn', 'Unknown')}")

    # Step 1 — Load SOC playbook
    playbook = load_playbook("playbooks/soc_rules_v1.json")
    print(f"\n[SOC] Loaded playbook v{playbook['version']}")

    # Step 2 — Query Investigation Memory
    print("\n[SOC] Querying investigation memory...")
    past_cases = memory.search(
        iocs=[alert.get("source_ip", "")],
        attack_pattern=alert.get("event_type", "")
    )
    memory_context = ""
    if past_cases:
        print(f"[SOC] ⚠ Memory hit — {len(past_cases)} past case(s) "
              f"found for this IOC")
        for c in past_cases:
            print(f"      → {c.get('id', 'Unknown')} | {c.get('severity', 'Unknown')} | "
                  f"{c.get('attack_pattern', 'Unknown')}")
            memory_context += (
                f"Past case {c.get('id', 'Unknown')}: severity={c.get('severity', 'Unknown')}, "
                f"pattern={c.get('attack_pattern', 'Unknown')}, "
                f"summary={c.get('summary', 'Unknown')}\n"
            )
    else:
        print("[SOC] No past cases found for this IOC")

    # Step 3 — Build Gemini prompt
    raw_logs = "\n".join(alert.get("raw_logs", []))
    prompt = f"""You are a Tier-1 SOC analyst performing alert triage.

ALERT DETAILS:
- Alert ID: {alert.get('alert_id', 'Unknown')}
- Timestamp: {alert.get('timestamp', 'Unknown')}
- Source IP: {alert.get('source_ip', 'Unknown')}
- Destination: {alert.get('destination', 'Unknown')}
- Event Type: {alert.get('event_type', 'Unknown')}
- Country: {alert.get('geolocation', {}).get('country', 'Unknown')}
- ASN: {alert.get('geolocation', {}).get('asn', 'Unknown')}
- Username: {alert.get('user_context', {}).get('username', 'Unknown')}
- Last Login: {alert.get('user_context', {}).get('last_login', 'Unknown')}

RAW LOGS:
{raw_logs}

SOC RULES:
- High risk ASNs: {playbook.get('high_risk_asns', [])}
- High risk countries: {playbook.get('high_risk_countries', [])}
- Authorized pentest ranges: {playbook.get('authorized_pentest_ranges', [])}
- Threat score weights: {json.dumps(playbook.get('threat_score_weights', {}))}
- Escalation threshold: {playbook.get('escalation_threshold', 60)}
- False positive threshold: {playbook.get('false_positive_threshold', 20)}

PAST INVESTIGATION MEMORY:
{memory_context if memory_context else "No prior cases found for this IOC."}

INSTRUCTIONS:
Analyze this alert step by step:
1. Check if source IP is in authorized pentest range
2. Assess IP reputation based on ASN and country
3. Identify behavioral patterns in the logs
4. Check for MITRE ATT&CK tactics
5. Calculate threat score using the weights provided
6. Make a triage decision: FALSE_POSITIVE, SUSPICIOUS, or ESCALATE
7. State your confidence (0.0 to 1.0)

Respond ONLY with a JSON object in this exact format:
{{
  "decision": "ESCALATE",
  "threat_score": 84,
  "agent_confidence": 0.91,
  "tactics_identified": ["T1110 - Brute Force", "T1078 - Valid Accounts"],
  "false_positive_reason": null,
  "escalation_reason": "Brief reason here",
  "reasoning_steps": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ]
}}
"""

    # Step 4 — Call Gemini
    print("\n[SOC] Running Gemini analysis...")
    from google import genai
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    response = client.models.generate_content(
        model=model_name,
        contents=prompt
    )
    raw = response.text.strip()

    # Step 5 — Parse response
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    result = json.loads(raw.strip())

    # Step 6 — Print reasoning steps
    print("\n[SOC] Reasoning steps:")
    for step in result.get("reasoning_steps", []):
        print(f"      {step}")

    # Step 7 — Print decision
    print(f"\n[SOC] Threat Score   : {result.get('threat_score', 0)}/100")
    print(f"[SOC] Confidence     : {result.get('agent_confidence', 0.0)}")
    print(f"[SOC] Decision       : {result.get('decision', 'UNKNOWN')}")
    if result.get("tactics_identified"):
        print(f"[SOC] Tactics        : "
              f"{', '.join(result.get('tactics_identified', []))}")
    if result.get("escalation_reason"):
        print(f"[SOC] Reason         : {result.get('escalation_reason', '')}")
    if result.get("false_positive_reason"):
        print(f"[SOC] FP Reason      : {result.get('false_positive_reason', '')}")

    # Step 8 — Build final report
    report = {
        "alert_id": alert.get("alert_id", "Unknown"),
        "decision": result.get("decision", "UNKNOWN"),
        "threat_score": result.get("threat_score", 0),
        "agent_confidence": result.get("agent_confidence", 0.0),
        "tactics_identified": result.get("tactics_identified", []),
        "memory_references": [c.get("id", "Unknown") for c in past_cases],
        "false_positive_reason": result.get("false_positive_reason"),
        "escalation_reason": result.get("escalation_reason"),
        "playbook_version": f"soc_rules_v{playbook.get('version', '1')}"
    }

    return report
