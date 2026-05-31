from pathlib import Path
import sqlite3
import json
import os
from dotenv import load_dotenv

load_dotenv()


class InvestigationMemory:
    def __init__(self):
        db_path = os.getenv("MEMORY_DB_PATH", "./data/memory.db")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                alert_id TEXT,
                timestamp TEXT,
                severity TEXT,
                attack_pattern TEXT,
                agent_confidence REAL,
                judge_score REAL,
                confidence_drift REAL,
                playbook_version TEXT,
                summary TEXT
            );

            CREATE TABLE IF NOT EXISTS iocs (
                investigation_id TEXT,
                ioc_type TEXT,
                ioc_value TEXT,
                FOREIGN KEY (investigation_id)
                    REFERENCES investigations(id)
            );

            CREATE TABLE IF NOT EXISTS tactics (
                investigation_id TEXT,
                mitre_id TEXT,
                tactic_name TEXT,
                FOREIGN KEY (investigation_id)
                    REFERENCES investigations(id)
            );
        """)
        self.conn.commit()

    def store(self, report: dict) -> None:
        self.conn.execute("""
            INSERT OR REPLACE INTO investigations VALUES
            (?,?,?,?,?,?,?,?,?,?)
        """, (
            report.get("investigation_id"),
            report.get("alert_id"),
            report.get("timestamp", ""),
            report.get("severity", ""),
            report.get("attack_pattern", ""),
            report.get("agent_confidence", 0.0),
            report.get("judge_score", 0.0),
            report.get("confidence_drift", 0.0),
            report.get("playbook_version", "v1"),
            report.get("summary", "")
        ))
        for ioc in report.get("iocs", {}).get("ips", []):
            ioc_value = ioc.get("address") if isinstance(ioc, dict) else ioc
            if ioc_value:
                self.conn.execute(
                    "INSERT INTO iocs VALUES (?,?,?)",
                    (report["investigation_id"], "ip", ioc_value)
                )
        for t in report.get("tactics_identified", []):
            parts = t.split(" - ", 1)
            self.conn.execute(
                "INSERT INTO tactics VALUES (?,?,?)",
                (report["investigation_id"],
                 parts[0] if len(parts) > 1 else t,
                 parts[1] if len(parts) > 1 else t)
            )
        self.conn.commit()

    def search(self, iocs=None, attack_pattern=None) -> list[dict]:
        results = []
        if iocs:
            for ioc in iocs:
                rows = self.conn.execute("""
                    SELECT i.* FROM investigations i
                    JOIN iocs c ON i.id = c.investigation_id
                    WHERE c.ioc_value = ?
                    ORDER BY i.timestamp DESC LIMIT 5
                """, (ioc,)).fetchall()
                results.extend(self._rows_to_dicts(rows))
        if attack_pattern:
            rows = self.conn.execute("""
                SELECT * FROM investigations
                WHERE attack_pattern LIKE ?
                ORDER BY timestamp DESC LIMIT 5
            """, (f"%{attack_pattern}%",)).fetchall()
            results.extend(self._rows_to_dicts(rows))
        seen = {}
        for r in results:
            seen[r["id"]] = r
        return list(seen.values())

    def get_related_cases(self,
                          iocs: list[str],
                          attack_pattern: str,
                          limit: int = 5) -> list[dict]:
        return self.search(iocs=iocs,
                           attack_pattern=attack_pattern)[:limit]

    def get_drift_history(self, last_n: int = 10) -> list[dict]:
        rows = self.conn.execute("""
            SELECT id, agent_confidence, judge_score,
                   confidence_drift, severity
            FROM investigations
            ORDER BY timestamp DESC LIMIT ?
        """, (last_n,)).fetchall()
        return [
            {
                "id": r[0],
                "agent_confidence": r[1],
                "judge_score": r[2],
                "drift": r[3],
                "severity": r[4]
            }
            for r in rows
        ]

    def _rows_to_dicts(self, rows) -> list[dict]:
        cols = ["id", "alert_id", "timestamp", "severity",
                "attack_pattern", "agent_confidence",
                "judge_score", "confidence_drift",
                "playbook_version", "summary"]
        return [dict(zip(cols, r)) for r in rows]

    def close(self):
        self.conn.close()
