import os
import sys
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from dotenv import load_dotenv

# Ensure the project root is in sys.path so 'agent' can be imported as a module
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

load_dotenv()

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
        return {
            "decision": "ESCALATE",
            "investigation_id": phantom_report["investigation_id"],
            "severity": phantom_report.get("severity"),
            "dfir_score": judge_result.get("dfir_quality_score"),
            "soc_score": judge_result.get("soc_quality_score"),
            "drift": judge_result["confidence_drift"]["severity"],
            "memory_references": phantom_report.get("memory_references", [])
        }


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
                    "GET /health": "Health check"
                },
                "phoenix_project": os.getenv(
                    "PHOENIX_PROJECT_NAME", "phantomsoc"
                )
            })
        elif self.path == "/trend":
            try:
                memory = InvestigationMemory()
                trend = memory.get_quality_trend(last_n=20)
                memory.close()
                self._send_json(200, {
                    "trend": trend,
                    "count": len(trend)
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
                alert = json.loads(body)
                memory = InvestigationMemory()
                judge_results = []
                result = run_investigation(alert, memory, judge_results)
                memory.close()
                self._send_json(200, result)
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
