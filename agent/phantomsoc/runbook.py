import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def generate_runbook(
    alert: dict,
    phantom_report: dict,
    breach_risk: dict
) -> dict:
    """
    Generate a step-by-step incident response runbook
    using Gemini. Returns structured runbook dict.
    """
    from google import genai
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    severity = phantom_report.get("severity", "MEDIUM")
    attack_chain = phantom_report.get("attack_chain", "Unknown")
    iocs = phantom_report.get("iocs", {})
    techniques = iocs.get("techniques", [])
    exfil = phantom_report.get("exfiltration", {})
    lateral = phantom_report.get("lateral_movement_found", False)
    persistence = phantom_report.get("persistence_found", False)
    risk_score = breach_risk.get("risk_score", 0)
    gdpr = breach_risk.get("gdpr_72hr_deadline", False)
    records = breach_risk.get("affected_records", 0)

    prompt = f"""You are a senior incident response engineer.
Generate a detailed incident response runbook for this security incident.

INCIDENT SUMMARY:
- Alert ID: {alert.get('alert_id')}
- Source IP: {alert.get('source_ip')} ({alert.get('geolocation',{}).get('country','Unknown')})
- Event Type: {alert.get('event_type')}
- Severity: {severity}
- Attack Chain: {attack_chain}
- MITRE Techniques: {', '.join(techniques) if techniques else 'None identified'}
- Lateral Movement: {lateral}
- Persistence Detected: {persistence}
- Exfiltration Confirmed: {exfil.get('confirmed', False)}
- Affected Records: {records:,}
- Risk Score: {risk_score}/100
- GDPR 72h Notification Required: {gdpr}

Generate a complete incident response runbook with these exact phases.
Each step must be specific and actionable, not generic.
Reference the actual IOCs, IPs, and techniques from this incident.

Respond ONLY with JSON (no markdown, no backticks):
{{
  "runbook_id": "RB-{alert.get('alert_id', 'UNKNOWN')}",
  "generated_at": "{datetime.utcnow().isoformat()}",
  "severity": "{severity}",
  "title": "Incident Response Runbook: [brief incident title]",
  "phases": {{
    "immediate_containment": {{
      "time_target": "0-15 minutes",
      "owner": "SOC Analyst",
      "steps": [
        "Step 1: specific action with exact command or procedure",
        "Step 2: ...",
        "Step 3: ..."
      ]
    }},
    "investigation": {{
      "time_target": "15-60 minutes",
      "owner": "DFIR Team",
      "steps": [
        "Step 1: ...",
        "Step 2: ...",
        "Step 3: ..."
      ]
    }},
    "eradication": {{
      "time_target": "1-4 hours",
      "owner": "Security Engineer",
      "steps": [
        "Step 1: ...",
        "Step 2: ...",
        "Step 3: ..."
      ]
    }},
    "recovery": {{
      "time_target": "4-24 hours",
      "owner": "IT Operations",
      "steps": [
        "Step 1: ...",
        "Step 2: ...",
        "Step 3: ..."
      ]
    }},
    "post_incident": {{
      "time_target": "24-72 hours",
      "owner": "Security Manager",
      "steps": [
        "Step 1: ...",
        "Step 2: ...",
        "Step 3: ..."
      ]
    }}
  }},
  "gdpr_actions": {json.dumps(["Notify DPA within 72 hours", "Document breach details", "Notify affected individuals"] if gdpr else [])},
  "iocs_to_block": {{
    "ips": {json.dumps([alert.get('source_ip', '')])},
    "techniques": {json.dumps(techniques)}
  }},
  "estimated_resolution_hours": 24,
  "auto_generated": true
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


def save_runbook_to_gcs(runbook: dict) -> str:
    """Save runbook to GCS and return the GCS path."""
    import json
    bucket_name = os.getenv("GCS_BUCKET", "")
    if not bucket_name:
        return ""
    try:
        from agent.core.storage import get_storage_client
        client = get_storage_client()
        if not client:
            return ""
        bucket = client.bucket(bucket_name)
        runbook_id = runbook.get("runbook_id", "unknown")
        path = f"runbooks/{runbook_id}.json"
        blob = bucket.blob(path)
        blob.upload_from_string(
            json.dumps(runbook, indent=2),
            content_type="application/json"
        )
        print(f"[Runbook] Saved to gs://{bucket_name}/{path}")
        return f"gs://{bucket_name}/{path}"
    except Exception as e:
        print(f"[Runbook] GCS save failed: {e}")
        return ""


def list_runbooks() -> list:
    """List all runbooks stored in GCS."""
    bucket_name = os.getenv("GCS_BUCKET", "")
    if not bucket_name:
        return []
    try:
        from agent.core.storage import get_storage_client
        client = get_storage_client()
        if not client:
            return []
        bucket = client.bucket(bucket_name)
        blobs = bucket.list_blobs(prefix="runbooks/")
        result = []
        for blob in blobs:
            if blob.name.endswith(".json"):
                data = json.loads(blob.download_as_text())
                result.append({
                    "runbook_id": data.get("runbook_id"),
                    "title": data.get("title"),
                    "severity": data.get("severity"),
                    "generated_at": data.get("generated_at"),
                    "gcs_path": f"gs://{bucket_name}/{blob.name}"
                })
        return sorted(result, key=lambda x: x.get(
            "generated_at", ""), reverse=True)
    except Exception as e:
        print(f"[Runbook] List failed: {e}")
        return []
