# PhantomSOC

**Autonomous Incident Response Platform that learns from every 
investigation it runs.**

Built for the Google Cloud Rapid Agent Hackathon — Arize Track.

---

## What It Does

PhantomSOC is a self-improving autonomous Security Operations 
Center (SOC) platform. Every investigation is traced by Arize 
Phoenix, evaluated by an LLM judge, and fed into a Learning 
Agent that rewrites detection and forensic playbooks — making 
the system measurably better with every case.

---

## Architecture
Alert Input
↓
Layer 1 — SOC Triage Agent
Classifies alerts, reduces false positives
References investigation memory for past IOC matches
↓ (ESCALATE only)
Layer 2 — Phantom Forensic Agent
Reconstructs attack timeline
Extracts IOCs and maps MITRE ATT&CK chain
Generates executive incident report
↓
LLM Judge + Confidence Drift Detector
Scores investigation quality (0-100%)
Flags overconfidence mismatches
↓
Investigation Memory Store (SQLite)
Persists all findings for future reference
↓ (every N investigations)
Layer 3 — Learning Meta-Agent
Queries Arize Phoenix MCP for trace data
Identifies systematic blind spots
Rewrites SOC and DFIR playbooks automatically

---

## Tech Stack

| Component | Technology |
|---|---|
| Agent Runtime | Google ADK |
| LLM | Gemini 3.1 Flash Lite |
| Observability | Arize Phoenix Cloud |
| Tracing | OpenInference (google-genai instrumentor) |
| Phoenix MCP | @arizeai/phoenix-mcp |
| Memory Store | SQLite |
| Hosting | Google Cloud Run |

> Note: Google ADK was chosen as the agent runtime because the 
> Arize track requires a code-owned runtime for direct 
> OpenInference instrumentation. Visual Agent Builder alone 
> does not support tracing integration.

---

## Self-Improvement Loop
Gemini investigates incident
↓
Phoenix traces every reasoning step
↓
LLM Judge scores quality + detects confidence drift
↓
Learning Agent queries Phoenix MCP for trace patterns
↓
Blind spots identified → Playbooks rewritten
↓
Next investigation uses updated playbooks

---

## Demo Results

| Metric | Before Learning | After Learning |
|---|---|---|
| DFIR Quality Score | 58% | 77% |
| SOC Quality Score | 50% | 65% |
| Confidence Drift | CRITICAL | WARNING |
| Memory Recall | No | Yes |
| Playbook Version | v1 | v2 |

---

## Project Structure
phantomsoc/
├── agent/
│   ├── instrumentation.py      # Arize Phoenix tracing setup
│   ├── main.py                 # Pipeline orchestrator
│   └── phantomsoc/
│       ├── models.py           # Pydantic schemas
│       ├── memory.py           # Investigation memory (SQLite)
│       ├── soc_agent.py        # Layer 1: SOC Triage Agent
│       ├── phantom_agent.py    # Layer 2: Phantom Forensic Agent
│       ├── judge.py            # LLM Judge + drift detection
│       ├── learning_agent.py   # Layer 3: Learning Meta-Agent
│       └── data/               # Simulated attack scenarios
├── playbooks/                  # SOC and DFIR playbooks (auto-versioned)
├── reports/                    # Generated investigation reports
├── .gemini/
│   └── settings.json           # Phoenix MCP configuration
└── .env.example                # Environment variable template

---

## Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- Google AI Studio API key
- Arize Phoenix Cloud account (free tier)

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/phantomsoc
cd phantomsoc
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
cp .env.example .env
# Fill in your API keys in .env
```

### Run

```bash
python agent/main.py
```

---

## Environment Variables

```bash
GOOGLE_API_KEY=your_gemini_api_key
PHOENIX_API_KEY=your_phoenix_api_key
PHOENIX_COLLECTOR_ENDPOINT=https://app.phoenix.arize.com/s/your-space/v1/traces
PHOENIX_PROJECT_NAME=phantomsoc
GOOGLE_CLOUD_PROJECT=phantomsoc-2026
GEMINI_MODEL=gemini-3.1-flash-lite
MEMORY_DB_PATH=./data/memory.db
LEARNING_AGENT_TRIGGER_N=3
CONFIDENCE_DRIFT_THRESHOLD=0.15
```

---

## Live Traces

View PhantomSOC traces in Arize Phoenix:
https://app.phoenix.arize.com/s/ssure-kumar01111

---

## License

Apache-2.0 — see LICENSE
