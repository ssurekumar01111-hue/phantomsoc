import os
import json
from dotenv import load_dotenv

load_dotenv()

ANALYST_HOURLY_RATE = 45  # USD, industry average
MINUTES_PER_FP_INVESTIGATION = 12
MINUTES_PER_REAL_INVESTIGATION = 45
BREACH_COST_PER_RECORD = 165  # IBM 2024 report


def calculate_cost_impact(
    total_alerts: int,
    fp_count: int,
    real_count: int,
    baseline_fp_rate: float = 0.80
) -> dict:
    """
    Calculate analyst time and cost saved by PhantomSOC triage.
    baseline_fp_rate: industry average false positive rate before PhantomSOC
    """
    # Before PhantomSOC — analyst handles everything manually
    baseline_fp = int(total_alerts * baseline_fp_rate)
    baseline_real = total_alerts - baseline_fp
    baseline_hours = (
        (baseline_fp * MINUTES_PER_FP_INVESTIGATION) +
        (baseline_real * MINUTES_PER_REAL_INVESTIGATION)
    ) / 60
    baseline_cost = baseline_hours * ANALYST_HOURLY_RATE

    # After PhantomSOC — only real threats reach analyst
    after_hours = (
        (fp_count * 1) +  # PhantomSOC handles FPs in seconds
        (real_count * MINUTES_PER_REAL_INVESTIGATION)
    ) / 60
    after_cost = after_hours * ANALYST_HOURLY_RATE

    hours_saved = round(baseline_hours - after_hours, 2)
    cost_saved = round(baseline_cost - after_cost, 2)
    fp_reduction_pct = round(
        (1 - fp_count / max(baseline_fp, 1)) * 100, 1
    )

    return {
        "total_alerts_processed": total_alerts,
        "false_positives_filtered": fp_count,
        "real_threats_escalated": real_count,
        "analyst_hours_before": round(baseline_hours, 2),
        "analyst_hours_after": round(after_hours, 2),
        "analyst_hours_saved": hours_saved,
        "cost_before_usd": round(baseline_cost, 2),
        "cost_after_usd": round(after_cost, 2),
        "cost_saved_usd": cost_saved,
        "fp_reduction_pct": fp_reduction_pct,
        "roi_multiplier": round(baseline_cost / max(after_cost, 0.01), 1)
    }


def calculate_breach_risk(phantom_report: dict) -> dict:
    """
    Calculate financial risk and breach severity from investigation findings.
    """
    exfil = phantom_report.get("exfiltration", {})
    records = exfil.get("records") or 0
    confirmed = exfil.get("confirmed", False)
    severity = phantom_report.get("severity", "LOW")
    lateral = phantom_report.get("lateral_movement_found", False)
    persistence = phantom_report.get("persistence_found", False)
    iocs = phantom_report.get("iocs", {})
    techniques = iocs.get("techniques", [])

    # Risk scoring
    risk_score = 0
    if severity == "CRITICAL":
        risk_score += 40
    elif severity == "HIGH":
        risk_score += 25
    elif severity == "MEDIUM":
        risk_score += 10

    if confirmed:
        risk_score += 25
    if lateral:
        risk_score += 15
    if persistence:
        risk_score += 10
    if records > 10000:
        risk_score += 10

    risk_score = min(risk_score, 100)

    # Financial impact
    estimated_breach_cost = records * BREACH_COST_PER_RECORD if records else 0
    regulatory_risk = records > 0  # GDPR/CCPA notification likely

    # Likelihood label
    if risk_score >= 80:
        likelihood = "Critical"
    elif risk_score >= 60:
        likelihood = "High"
    elif risk_score >= 40:
        likelihood = "Medium"
    else:
        likelihood = "Low"

    return {
        "risk_score": risk_score,
        "likelihood": likelihood,
        "estimated_breach_cost_usd": estimated_breach_cost,
        "affected_records": records,
        "exfiltration_confirmed": confirmed,
        "lateral_movement": lateral,
        "persistence_detected": persistence,
        "regulatory_notification_required": regulatory_risk,
        "gdpr_72hr_deadline": regulatory_risk,
        "mitre_techniques": techniques
    }


def generate_stakeholder_reports(
    alert: dict,
    soc_report: dict,
    phantom_report: dict,
    breach_risk: dict,
    cost_impact: dict
) -> dict:
    """
    Generate four stakeholder reports using one Gemini call.
    Returns dict with soc_analyst, security_manager, executive, compliance.
    """
    from google import genai
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

    prompt = f"""You are a security report writer generating four versions
of the same incident for different audiences.

INCIDENT DATA:
- Alert ID: {alert.get('alert_id')}
- Source IP: {alert.get('source_ip')} ({alert.get('geolocation',{}).get('country')})
- Event: {alert.get('event_type')}
- Attack Chain: {phantom_report.get('attack_chain', 'N/A')}
- Severity: {phantom_report.get('severity')}
- Exfiltration: {phantom_report.get('exfiltration', {})}
- Persistence: {phantom_report.get('persistence_found')}
- Lateral Movement: {phantom_report.get('lateral_movement_found')}
- Risk Score: {breach_risk.get('risk_score')}/100
- Estimated Breach Cost: ${breach_risk.get('estimated_breach_cost_usd'):,}
- Affected Records: {breach_risk.get('affected_records')}
- GDPR Notification Required: {breach_risk.get('gdpr_72hr_deadline')}
- Analyst Hours Saved: {cost_impact.get('analyst_hours_saved')}
- Cost Saved: ${cost_impact.get('cost_saved_usd')}

Generate four reports. Be concise. Each under 150 words.

Respond ONLY with JSON:
{{
  "soc_analyst": {{
    "title": "Technical Incident Report",
    "content": "Technical details for SOC analyst including IOCs,
attack chain, MITRE techniques, recommended containment steps."
  }},
  "security_manager": {{
    "title": "Security Risk Summary",
    "content": "Risk level, what was compromised, team actions needed,
timeline, current status. Written for security manager."
  }},
  "executive": {{
    "title": "Executive Briefing",
    "content": "Business impact, financial exposure, customer impact,
what we are doing. Non-technical. Under 100 words."
  }},
  "compliance": {{
    "title": "Compliance & Regulatory Report",
    "content": "GDPR/CCPA notification requirements, 72-hour deadline
if applicable, PII exposure, records affected, recommended legal actions."
  }}
}}"""

    response = client.models.generate_content(
        model=model_name,
        contents=prompt
    )
    raw = response.text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())
