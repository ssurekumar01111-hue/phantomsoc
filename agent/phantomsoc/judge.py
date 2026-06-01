import os
import json
from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

load_dotenv()

def detect_confidence_drift(investigation_id: str,
                             agent_confidence: float,
                             judge_score: float) -> dict:
    drift = round(agent_confidence - judge_score, 3)
    if drift >= 0.30:
        severity = "CRITICAL"
        label = "Severe overconfidence — agent unreliable"
    elif drift >= 0.15:
        severity = "WARNING"
        label = "Moderate overconfidence — quality overstated"
    elif drift <= -0.15:
        severity = "INFO"
        label = "Underconfidence — agent undersells quality"
    else:
        severity = "OK"
        label = "Confidence well calibrated"
    return {
        "investigation_id": investigation_id,
        "agent_confidence": agent_confidence,
        "judge_score": judge_score,
        "drift": drift,
        "severity": severity,
        "label": label
    }


def run_judge(soc_report: dict,
              phantom_report: dict | None = None) -> dict:
    """
    LLM-as-a-Judge evaluator.
    Scores SOC triage quality and optionally DFIR investigation quality.
    """
    print("\n" + "="*60)
    print("LLM JUDGE — EVALUATION")
    print("="*60)

    from google import genai
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

    # Score SOC triage
    soc_prompt = f"""You are an expert SOC quality evaluator.

Score this SOC triage report on a scale of 0.0 to 1.0 based on:
- Did it check IP/ASN reputation? (15%)
- Did it check geolocation anomaly? (10%)
- Did it reference investigation memory if available? (20%)
- Did it identify MITRE ATT&CK tactics? (25%)
- Was the decision justified with evidence? (25%)
- Was the false positive correctly handled? (5%)

SOC REPORT:
{json.dumps(soc_report, indent=2)}

Respond ONLY with JSON:
{{
  "score": 0.85,
  "feedback": "Brief feedback on what was good and what was missed"
}}"""

    soc_response = client.models.generate_content(
        model=model_name,
        contents=soc_prompt
    )
    soc_raw = soc_response.text.strip()
    if soc_raw.startswith("```"):
        soc_raw = soc_raw.split("```")[1]
        if soc_raw.startswith("json"):
            soc_raw = soc_raw[4:]
    soc_eval = json.loads(soc_raw.strip())

    soc_score = soc_eval["score"]
    print(f"[Judge] SOC Quality Score : {soc_score:.2f}")
    print(f"[Judge] SOC Feedback      : {soc_eval['feedback']}")

    dfir_score = None
    dfir_feedback = ""

    # Score DFIR investigation if provided
    if phantom_report:
        dfir_prompt = f"""You are an expert DFIR quality evaluator.

Score this forensic investigation report on a scale of 0.0 to 1.0:
- Timeline reconstruction complete? (12%)
- IOCs fully extracted? (12%)
- Investigation memory referenced? (12%)
- MITRE ATT&CK mapping accurate? (15%)
- Lateral movement checked? (12%)
- Persistence mechanisms checked? (12%)
- Exfiltration assessed? (12%)
- Executive report clear and business-readable? (13%)

DFIR REPORT:
{json.dumps(phantom_report, indent=2)}

Respond ONLY with JSON:
{{
  "score": 0.72,
  "feedback": "Brief feedback on what was covered and what was missed"
}}"""

        dfir_response = client.models.generate_content(
            model=model_name,
            contents=dfir_prompt
        )
        dfir_raw = dfir_response.text.strip()
        if dfir_raw.startswith("```"):
            dfir_raw = dfir_raw.split("```")[1]
            if dfir_raw.startswith("json"):
                dfir_raw = dfir_raw[4:]
        dfir_eval = json.loads(dfir_raw.strip())

        dfir_score = dfir_eval["score"]
        dfir_feedback = dfir_eval["feedback"]
        print(f"[Judge] DFIR Quality Score: {dfir_score:.2f}")
        print(f"[Judge] DFIR Feedback     : {dfir_feedback}")

    # Use best available score for drift detection
    primary_score = dfir_score if dfir_score is not None else soc_score
    agent_conf = (phantom_report or soc_report).get(
        "agent_confidence", 0.8
    )
    inv_id = (phantom_report or soc_report).get(
        "investigation_id",
        soc_report.get("alert_id", "unknown")
    )

    drift = detect_confidence_drift(inv_id, agent_conf, primary_score)
    print(f"\n[Judge] Confidence Drift  : {drift['drift']:+.3f} "
          f"— {drift['severity']} — {drift['label']}")

    # Log evaluation scores back to Phoenix as span attributes
    try:
        tracer = trace.get_tracer("phantomsoc.judge")
        with tracer.start_as_current_span("llm_judge_evaluation") as span:
            span.set_attribute("eval.soc_quality_score", soc_score)
            span.set_attribute("eval.dfir_quality_score", dfir_score or 0.0)
            span.set_attribute("eval.confidence_drift", drift["drift"])
            span.set_attribute("eval.drift_severity", drift["severity"])
            span.set_attribute("eval.agent_confidence", agent_conf)
            span.set_attribute("eval.investigation_id", inv_id)
            span.set_attribute("eval.soc_feedback", soc_eval["feedback"])
            if dfir_score:
                span.set_attribute("eval.dfir_feedback", dfir_feedback)
            print(f"[Phoenix] Judge scores logged to Phoenix span")
    except Exception as e:
        print(f"[Phoenix] Warning: could not log judge span: {e}")

    return {
        "investigation_id": inv_id,
        "soc_quality_score": soc_score,
        "dfir_quality_score": dfir_score,
        "soc_feedback": soc_eval["feedback"],
        "dfir_feedback": dfir_feedback,
        "confidence_drift": drift
    }


