import os
import json
from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from pydantic import BaseModel, Field, validator
from typing import Optional

load_dotenv()

class DriftResult(BaseModel):
    drift: float = Field(default=0.0)
    severity: str = Field(default="OK")
    message: str = Field(default="")

    @validator('severity')
    def severity_must_be_valid(cls, v):
        valid = {"OK", "INFO", "WARNING", "CRITICAL"}
        return v if v in valid else "WARNING"

    @validator('drift')
    def drift_must_be_float(cls, v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

class JudgeEvaluation(BaseModel):
    soc_quality_score: float = Field(default=0.5, ge=0.0, le=1.0)
    dfir_quality_score: float = Field(default=0.5, ge=0.0, le=1.0)
    soc_feedback: str = Field(default="Evaluation unavailable")
    dfir_feedback: str = Field(default="Evaluation unavailable")
    confidence_drift: DriftResult = Field(
        default_factory=DriftResult
    )

    @validator('soc_quality_score', 'dfir_quality_score',
               pre=True)
    def clamp_score(cls, v):
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 0.5


def fallback_safe_evaluation(error: str = "") -> dict:
    """
    Returns a safe baseline evaluation when judge fails.
    Prevents pipeline crashes from corrupted log chunks.
    """
    print(f"[Judge] Warning: using fallback evaluation"
          f"{': ' + error if error else ''}")
    return JudgeEvaluation(
        soc_quality_score=0.5,
        dfir_quality_score=0.5,
        soc_feedback="Evaluation unavailable - fallback triggered",
        dfir_feedback="Evaluation unavailable - fallback triggered",
        confidence_drift=DriftResult(
            drift=0.0,
            severity="WARNING",
            message="Judge fallback - manual review required"
        )
    ).dict()


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

    try:
        tracer = trace.get_tracer("phantomsoc.judge")
        with tracer.start_as_current_span("llm_judge_evaluation") as span:
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
  "soc_quality_score": 0.85,
  "soc_feedback": "Brief feedback on what was good and what was missed"
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

            # Score DFIR investigation if provided
            dfir_score = None
            dfir_feedback = ""
            dfir_eval = {}

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
  "dfir_quality_score": 0.72,
  "dfir_feedback": "Brief feedback on what was covered and what was missed"
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
                dfir_score = dfir_eval.get("dfir_quality_score")
                dfir_feedback = dfir_eval.get("dfir_feedback")

            # Parse result
            try:
                parsed_json = {
                    "soc_quality_score": soc_eval.get("soc_quality_score"),
                    "dfir_quality_score": dfir_score if dfir_score is not None else 0.5,
                    "soc_feedback": soc_eval.get("soc_feedback"),
                    "dfir_feedback": dfir_feedback
                }
                evaluation = JudgeEvaluation(**parsed_json)
                result = evaluation.dict()
            except Exception as parse_error:
                print(f"[Judge] Parse error: {parse_error}")
                result = fallback_safe_evaluation(str(parse_error))

            # Drift detection
            primary_score = result["dfir_quality_score"] if phantom_report else result["soc_quality_score"]
            agent_conf = (phantom_report or soc_report).get(
                "agent_confidence", 0.8
            )
            inv_id = (phantom_report or soc_report).get(
                "investigation_id",
                soc_report.get("alert_id", "unknown")
            )

            drift = detect_confidence_drift(inv_id, agent_conf, primary_score)
            result["confidence_drift"] = drift
            result["investigation_id"] = inv_id
            
            # Print status
            print(f"[Judge] SOC Quality Score : {result['soc_quality_score']:.2f}")
            print(f"[Judge] SOC Feedback      : {result['soc_feedback']}")
            if phantom_report:
                print(f"[Judge] DFIR Quality Score: {result['dfir_quality_score']:.2f}")
                print(f"[Judge] DFIR Feedback     : {result['dfir_feedback']}")
            print(f"\n[Judge] Confidence Drift  : {drift['drift']:+.3f} "
                  f"— {drift['severity']} — {drift['label']}")

            # Log evaluation scores back to Phoenix as span attributes
            span.set_attribute("eval.soc_quality_score", result["soc_quality_score"])
            span.set_attribute("eval.dfir_quality_score", result["dfir_quality_score"])
            span.set_attribute("eval.confidence_drift", drift["drift"])
            span.set_attribute("eval.drift_severity", drift["severity"])
            span.set_attribute("eval.agent_confidence", agent_conf)
            span.set_attribute("eval.investigation_id", inv_id)
            span.set_attribute("eval.soc_feedback", result["soc_feedback"])
            span.set_attribute("eval.dfir_feedback", result["dfir_feedback"])
            
            # Log breach risk to Phoenix if available
            if phantom_report and phantom_report.get("breach_risk"):
                br = phantom_report["breach_risk"]
                try:
                    span.set_attribute("breach.risk_score",
                                       br.get("risk_score", 0))
                    span.set_attribute("breach.financial_exposure_usd",
                                       br.get("estimated_breach_cost_usd", 0))
                    span.set_attribute("breach.affected_records",
                                       br.get("affected_records", 0))
                    span.set_attribute("breach.gdpr_required",
                                       br.get("gdpr_72hr_deadline", False))
                except Exception:
                    pass
            
            print(f"[Phoenix] Judge scores logged to Phoenix span")
            return result

    except Exception as e:
        print(f"[Judge] Error in evaluation: {e}")
        result = fallback_safe_evaluation(str(e))
        # Still log to Phoenix if possible
        try:
            span.set_attribute("judge.fallback_triggered", True)
            span.set_attribute("judge.fallback_reason", str(e))
        except Exception:
            pass
        return result
