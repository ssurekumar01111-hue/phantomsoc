from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class TriageDecision(str, Enum):
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUSPICIOUS = "SUSPICIOUS"
    ESCALATE = "ESCALATE"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class GeoLocation(BaseModel):
    country: str
    asn: str


class UserContext(BaseModel):
    username: str
    last_login: str


class Alert(BaseModel):
    alert_id: str
    timestamp: str
    source_ip: str
    destination: str
    event_type: str
    raw_logs: list[str]
    geolocation: GeoLocation
    user_context: UserContext


class MemoryReference(BaseModel):
    investigation_id: str
    summary: str
    severity: str
    relevance: str


class SOCReport(BaseModel):
    alert_id: str
    decision: TriageDecision
    threat_score: int = Field(ge=0, le=100)
    agent_confidence: float = Field(ge=0.0, le=1.0)
    tactics_identified: list[str]
    memory_references: list[str] = []
    false_positive_reason: Optional[str] = None
    escalation_reason: Optional[str] = None
    playbook_version: str


class IOCs(BaseModel):
    ips: list[str] = []
    domains: list[str] = []
    hashes: list[str] = []
    techniques: list[str] = []


class TimelineEvent(BaseModel):
    time: str
    event: str


class ExfiltrationAssessment(BaseModel):
    confirmed: bool
    volume: Optional[str] = None
    records: Optional[int] = None


class PhantomReport(BaseModel):
    investigation_id: str
    alert_id: str
    agent_confidence: float = Field(ge=0.0, le=1.0)
    playbook_version: str
    memory_references: list[str] = []
    timeline: list[TimelineEvent]
    iocs: IOCs
    attack_chain: str
    persistence_found: bool
    lateral_movement_found: bool
    exfiltration: ExfiltrationAssessment
    severity: Severity
    quality_score: Optional[float] = None


class DriftSeverity(str, Enum):
    OK = "OK"
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class ConfidenceDrift(BaseModel):
    investigation_id: str
    agent_confidence: float
    judge_score: float
    drift: float
    severity: DriftSeverity
    label: str


class JudgeResult(BaseModel):
    investigation_id: str
    soc_quality_score: float = Field(ge=0.0, le=1.0)
    dfir_quality_score: float = Field(ge=0.0, le=1.0)
    confidence_drift: ConfidenceDrift
    feedback: str


class PlaybookUpdate(BaseModel):
    version: int
    generated_by: str = "learning_agent"
    trigger_reason: str
    changes: list[str]


class LearningReport(BaseModel):
    cases_analyzed: int
    avg_soc_score: float
    avg_dfir_score: float
    critical_drift_events: int
    top_blind_spots: list[str]
    playbook_updates: list[PlaybookUpdate]
