import os
import sys
import json
import threading
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from dotenv import load_dotenv
from pydantic import BaseModel, Field, validator
from typing import List, Optional

# Ensure the project root is in sys.path so 'agent' can be imported as a module
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

load_dotenv()

class AlertInput(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=100)
    timestamp: str = Field(..., min_length=1, max_length=50)
    source_ip: str = Field(..., max_length=50)
    destination: Optional[str] = Field(None, max_length=200)
    event_type: str = Field(..., max_length=100)
    raw_logs: List[str] = Field(default_factory=list,
                                max_items=1000)
    geolocation: Optional[dict] = Field(default_factory=dict)
    user_context: Optional[dict] = Field(default_factory=dict)

    @validator('alert_id')
    def sanitize_alert_id(cls, v):
        # Prevent path traversal and injection
        if re.search(r'[.]{2}|[/\\]|[<>"\']', v):
            raise ValueError(
                "alert_id contains invalid characters"
            )
        return v

    @validator('source_ip')
    def sanitize_ip(cls, v):
        # Basic IP/hostname validation
        if re.search(r'[<>"\']|\.\.', v):
            raise ValueError("source_ip contains invalid characters")
        return v

    @validator('raw_logs')
    def sanitize_logs(cls, logs):
        # Truncate oversized log entries
        return [log[:2000] for log in logs[:1000]]

    @validator('event_type')
    def sanitize_event_type(cls, v):
        if re.search(r'[<>"\']|\.\.', v):
            raise ValueError(
                "event_type contains invalid characters"
            )
        return v

# Initialize Phoenix tracing FIRST before any agent imports
from agent.instrumentation import init_tracing
tracer_provider = init_tracing()

# Only import agents AFTER tracing is initialized
from agent.phantomsoc.memory import InvestigationMemory
from agent.phantomsoc.soc_agent import run_soc_agent
from agent.phantomsoc.phantom_agent import run_phantom_agent
from agent.phantomsoc.judge import run_judge
from agent.phantomsoc.learning_agent import run_learning_agent


from opentelemetry import trace

# Global investigation counter for Learning Agent trigger
_investigation_count = 0
_session_judge_results = []

def run_investigation(alert, memory, judge_results):
    tracer = trace.get_tracer("phantomsoc.server")
    with tracer.start_as_current_span("phantomsoc_pipeline") as root:
        root.set_attribute("alert.id", alert.get("alert_id",""))
        root.set_attribute("alert.source_ip", alert.get("source_ip",""))
        root.set_attribute("alert.event_type", alert.get("event_type",""))
        
        soc_report = run_soc_agent(alert, memory)
        if soc_report["decision"] != "ESCALATE":
            return {"decision": soc_report["decision"],
                    "alert_id": alert["alert_id"]}
        phantom_report = run_phantom_agent(alert, soc_report, memory)
        judge_result = run_judge(soc_report, phantom_report)
        judge_results.append(judge_result)
        memory.store({
            "investigation_id": phantom_report["investigation_id"],
            "alert_id": alert["alert_id"],
            "timestamp": alert["timestamp"],
            "severity": phantom_report.get("severity", "UNKNOWN"),
            "attack_pattern": alert["event_type"],
            "agent_confidence": phantom_report.get("agent_confidence", 0.0),
            "judge_score": judge_result.get("dfir_quality_score")
                           or judge_result.get("soc_quality_score", 0.0),
            "confidence_drift": judge_result["confidence_drift"]["drift"],
            "playbook_version": phantom_report.get("playbook_version", "v1"),
            "summary": (f"{alert['event_type']} from "
                        f"{alert['source_ip']} — "
                        f"severity={phantom_report.get('severity','UNKNOWN')}"),
            "iocs": phantom_report.get("iocs", {}),
            "tactics_identified": soc_report.get("tactics_identified", []),
            "breach_risk_score": (
                phantom_report.get("breach_risk", {})
                .get("risk_score", 0)
            ),
            "financial_exposure_usd": (
                phantom_report.get("breach_risk", {})
                .get("estimated_breach_cost_usd", 0)
            ),
            "affected_records": (
                phantom_report.get("breach_risk", {})
                .get("affected_records", 0)
            )
        })
        # Save to GCS trend log for persistence across restarts
        try:
            from agent.core.storage import save_trend_entry
            save_trend_entry({
                "id": phantom_report["investigation_id"],
                "timestamp": alert.get("timestamp", ""),
                "judge_score": (
                    judge_result.get("dfir_quality_score") or
                    judge_result.get("soc_quality_score", 0)
                ),
                "agent_confidence": phantom_report.get(
                    "agent_confidence", 0
                ),
                "drift": judge_result["confidence_drift"]["drift"],
                "breach_risk_score": phantom_report.get(
                    "breach_risk", {}
                ).get("risk_score", 0),
                "financial_exposure_usd": phantom_report.get(
                    "breach_risk", {}
                ).get("estimated_breach_cost_usd", 0),
                "playbook_version": phantom_report.get(
                    "playbook_version", "v1"
                )
            })
        except Exception as e:
            print(f"[Trend] GCS save failed: {e}")

        result_dict = {
            "decision": "ESCALATE",
            "investigation_id": phantom_report["investigation_id"],
            "severity": phantom_report.get("severity"),
            "dfir_score": judge_result.get("dfir_quality_score"),
            "soc_score": judge_result.get("soc_quality_score"),
            "drift": judge_result["confidence_drift"]["severity"],
            "memory_references": phantom_report.get(
                "memory_references", []
            ),
            "breach_risk": phantom_report.get("breach_risk", {}),
            "cost_impact": phantom_report.get("cost_impact", {}),
            "stakeholder_reports": phantom_report.get(
                "stakeholder_reports", {}
            ),
            "executive_report": phantom_report.get(
                "executive_report", ""
            ),
            "runbook": phantom_report.get("runbook", {}),
            "runbook_gcs_path": phantom_report.get(
                "runbook_gcs_path", ""
            )
        }

        # Track for Learning Agent
        global _investigation_count, _session_judge_results
        _investigation_count += 1
        _session_judge_results.append(judge_result)

        # Trigger Learning Agent every N real investigations
        trigger_n = int(os.getenv("LEARNING_AGENT_TRIGGER_N", 3))
        if _investigation_count % trigger_n == 0:
            print(f"\n[Server] Investigation #{_investigation_count}"
                  f" — triggering Learning Agent...")
            try:
                learning_report = run_learning_agent(
                    memory, _session_judge_results
                )
                print(f"[Server] Learning Agent complete — "
                      f"playbooks updated")
                # Save learning report to GCS
                try:
                    from agent.core.storage import save_report
                    import json
                    from datetime import datetime
                    report_content = (
                        f"Learning Agent Report\n"
                        f"Generated: {datetime.utcnow().isoformat()}\n"
                        f"Cases analyzed: {learning_report.get('cases_analyzed')}\n"
                        f"Avg DFIR score: {learning_report.get('avg_dfir_score')}\n"
                        f"Blind spots: {learning_report.get('top_blind_spots')}\n"
                        f"DFIR playbook: {learning_report.get('dfir_playbook_updated')}\n"
                        f"SOC playbook: {learning_report.get('soc_playbook_updated')}\n"
                    )
                    save_report(
                        f"learning-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
                        report_content
                    )
                except Exception as e:
                    print(f"[Server] Could not save learning report: {e}")
            except Exception as e:
                print(f"[Server] Learning Agent failed: {e}")

        return result_dict


class PhantomSOCHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress default logging

    def do_GET(self):
        if self.path == "/":
            self._send_json(200, {
                "service": "PhantomSOC",
                "status": "running",
                "description": (
                    "Autonomous Incident Response Platform"
                ),
                "version": "1.0.0",
                "tracks": "Google Cloud Rapid Agent Hackathon — Arize",
                "endpoints": {
                    "POST /investigate": "Run investigation on alert",
                    "POST /demo": "Run full demo pipeline",
                    "GET /trend": "Quality scores over time",
                    "GET /metrics": "Aggregated system metrics",
                    "GET /health": "Health check",
                    "GET /runbooks": "List all generated runbooks",
                    "POST /learn": "Manually trigger Learning Agent"
                },
                "phoenix_project": os.getenv(
                    "PHOENIX_PROJECT_NAME", "phantomsoc"
                )
            })
        elif self.path == "/trend":
            try:
                from agent.core.storage import load_trend_entries
                # Try GCS first for persistence
                gcs_trend = load_trend_entries()
                if gcs_trend:
                    self._send_json(200, {
                        "trend": gcs_trend,
                        "count": len(gcs_trend),
                        "source": "gcs"
                    })
                else:
                    # Fall back to local SQLite
                    memory = InvestigationMemory()
                    trend = memory.get_quality_trend(last_n=20)
                    memory.close()
                    self._send_json(200, {
                        "trend": trend,
                        "count": len(trend),
                        "source": "local"
                    })
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif self.path == "/metrics":
            try:
                memory = InvestigationMemory()
                trend = memory.get_quality_trend(last_n=20)
                drift_history = memory.get_drift_history(last_n=20)
                memory.close()
                
                scores = [t["judge_score"] for t in trend
                          if t["judge_score"]]
                exposures = [t["financial_exposure_usd"] for t in trend
                             if t["financial_exposure_usd"]]
                
                self._send_json(200, {
                    "total_investigations": len(trend),
                    "avg_quality_score": (
                        round(sum(scores)/len(scores), 3)
                        if scores else 0
                    ),
                    "total_financial_exposure_usd": sum(exposures),
                    "quality_trend": trend,
                    "drift_history": drift_history
                })
            except Exception as e:
                self._send_json(500, {"error": str(e)})
        elif self.path == "/health":
            self._send_json(200, {"status": "healthy"})
        elif self.path == "/runbooks":
            try:
                from agent.phantomsoc.runbook import list_runbooks
                books = list_runbooks()
                self._send_json(200, {
                    "runbooks": books,
                    "count": len(books)
                })
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif self.path == "/reports":
            try:
                bucket_name = os.getenv("GCS_BUCKET", "")
                if bucket_name:
                    from google.cloud import storage
                    client = storage.Client()
                    bucket = client.bucket(bucket_name)
                    blobs = list(bucket.list_blobs(prefix="reports/"))
                    reports = [b.name for b in blobs]
                    self._send_json(200, {
                        "reports": reports,
                        "count": len(reports),
                        "bucket": bucket_name
                    })
                else:
                    self._send_json(200, {
                        "reports": [],
                        "message": "GCS not configured"
                    })
            except Exception as e:
                self._send_json(500, {"error": str(e)})
        elif self.path == "/dashboard":
            try:
                with open("dashboard.html", "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", len(body))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            except FileNotFoundError:
                self._send_json(404, {"error": "Dashboard not found"})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        if self.path == "/investigate":
            try:
                raw_data = json.loads(body)
                # Anti-Telemetry Poisoning Guardrail
                alert = AlertInput(**raw_data).dict()
                memory = InvestigationMemory()
                judge_results = []
                result = run_investigation(alert, memory, judge_results)
                memory.close()
                self._send_json(200, result)
            except ValueError as ve:
                self._send_json(400, {
                    "error": "Input validation failed",
                    "detail": str(ve)
                })
                return
            except json.JSONDecodeError:
                self._send_json(400, {"error": "Invalid JSON"})
                return
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif self.path == "/learn":
            try:
                global _session_judge_results
                memory = InvestigationMemory()
                if not _session_judge_results:
                    self._send_json(200, {
                        "status": "skipped",
                        "reason": "No investigations in current session yet. Run /investigate first."
                    })
                    memory.close()
                    return
                
                print("\n[Server] Manual Learning Agent trigger via /learn")
                learning_report = run_learning_agent(
                    memory, _session_judge_results
                )
                memory.close()
                self._send_json(200, {
                    "status": "complete",
                    "cases_analyzed": learning_report.get("cases_analyzed"),
                    "avg_soc_score": learning_report.get("avg_soc_score"),
                    "avg_dfir_score": learning_report.get("avg_dfir_score"),
                    "top_blind_spots": learning_report.get("top_blind_spots"),
                    "dfir_playbook_updated": learning_report.get("dfir_playbook_updated"),
                    "soc_playbook_updated": learning_report.get("soc_playbook_updated")
                })
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif self.path == "/demo":
            try:
                def run_demo():
                    import glob
                    memory = InvestigationMemory()
                    judge_results = []
                    scenarios = sorted(
                        glob.glob("agent/phantomsoc/data/scenario_*.json")
                    )
                    results = []
                    for s in scenarios:
                        with open(s) as f:
                            alert = json.load(f)
                        r = run_investigation(alert, memory, judge_results)
                        results.append(r)
                    if judge_results:
                        run_learning_agent(memory, judge_results)
                    memory.close()
                    return results

                results = run_demo()
                self._send_json(200, {
                    "status": "demo_complete",
                    "investigations": results,
                    "phoenix_traces": (
                        "https://app.phoenix.arize.com"
                        "/s/ssure-kumar01111"
                    )
                })
            except Exception as e:
                self._send_json(500, {"error": str(e)})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def _send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)


def main():
    port = int(os.getenv("PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), PhantomSOCHandler)
    print(f"PhantomSOC server running on port {port}")
    print(f"Phoenix project: {os.getenv('PHOENIX_PROJECT_NAME')}")
    server.serve_forever()


if __name__ == "__main__":
    main()
