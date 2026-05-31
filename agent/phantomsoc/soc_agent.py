import os
import json
from dotenv import load_dotenv
import google.generativeai as genai
from agent.phantomsoc.memory import InvestigationMemory

load_dotenv()
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))


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
    print(f"[SOC] Alert ID      : {alert['alert_id']}")
    print(f"[SOC] Source IP     : {alert['source_ip']}")
    print(f"[SOC] Event Type    : {alert['event_type']}")
    print(f"[SOC] Country/ASN   : "
          f"{alert['geolocation']['country']} / "
          f"{alert['geolocation']['asn']}")

    # Step 1 — Load SOC playbook
    playbook = load_playbook("playbooks/soc_rules_v1.json")
    print(f"\n[SOC] Loaded playbook v{playbook['version']}")

    # Step 2 — Query Investigation Memory
    print("\n[SOC] Querying investigation memory...")
    past_cases = memory.search(
        iocs=[alert["source_ip"]],
        attack_pattern=alert["event_type"]
    )
    memory_context = ""
    if past_cases:
        print(f"[SOC] ⚠ Memory hit — {len(past_cases)} past case(s) "
              f"found for this IOC")
        for c in past_cases:
            print(f"      → {c['id']} | {c['severity']} | "
                  f"{c['attack_pattern']}")
            memory_context += (
                f"Past case {c['id']}: severity={c['severity']}, "
                f"pattern={c['attack_pattern']}, "
                f"summary={c['summary']}\n"
            )
    else:
        print("[SOC] No past cases found for this IOC")

    # Step 3 — Build Gemini prompt
    raw_logs = "\n".join(alert["raw_logs"])
    prompt = f"""You are a Tier-1 SOC analyst performing alert triage.

ALERT DETAILS:
- Alert ID: {alert['alert_id']}
- Timestamp: {alert['timestamp']}
- Source IP: {alert['source_ip']}
- Destination: {alert['destination']}
- Event Type: {alert['event_type']}
- Country: {alert['geolocation']['country']}
- ASN: {alert['geolocation']['asn']}
- Username: {alert['user_context']['username']}
- Last Login: {alert['user_context']['last_login']}

RAW LOGS:
{raw_logs}

SOC RULES:
- High risk ASNs: {playbook['high_risk_asns']}
- High risk countries: {playbook['high_risk_countries']}
- Authorized pentest ranges: {playbook['authorized_pentest_ranges']}
- Threat score weights: {json.dumps(playbook['threat_score_weights'])}
- Escalation threshold: {playbook['escalation_threshold']}
- False positive threshold: {playbook['false_positive_threshold']}

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
    model = genai.GenerativeModel(
        os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    )
    response = model.generate_content(prompt)
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
    print(f"\n[SOC] Threat Score   : {result['threat_score']}/100")
    print(f"[SOC] Confidence     : {result['agent_confidence']}")
    print(f"[SOC] Decision       : {result['decision']}")
    if result.get("tactics_identified"):
        print(f"[SOC] Tactics        : "
              f"{', '.join(result['tactics_identified'])}")
    if result.get("escalation_reason"):
        print(f"[SOC] Reason         : {result['escalation_reason']}")
    if result.get("false_positive_reason"):
        print(f"[SOC] FP Reason      : {result['false_positive_reason']}")

    # Step 8 — Build final report
    report = {
        "alert_id": alert["alert_id"],
        "decision": result["decision"],
        "threat_score": result["threat_score"],
        "agent_confidence": result["agent_confidence"],
        "tactics_identified": result.get("tactics_identified", []),
        "memory_references": [c["id"] for c in past_cases],
        "false_positive_reason": result.get("false_positive_reason"),
        "escalation_reason": result.get("escalation_reason"),
        "playbook_version": f"soc_rules_v{playbook['version']}"
    }

    return report
