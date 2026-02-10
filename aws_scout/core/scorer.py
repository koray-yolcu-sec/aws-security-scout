# aws_scout/core/scorer.py
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def normalize(cls, value: Any) -> "Severity":
        """
        value:
          - Severity enum olabilir
          - "HIGH" gibi string olabilir
          - None / bilinmeyen olabilir
        """
        if isinstance(value, Severity):
            return value
        if isinstance(value, str):
            v = value.strip().upper()
            if v in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return Severity(v)
        return Severity.LOW



class Finding:
    """
    Eski check'lerin kullandığı Finding imzasıyla uyumlu.
    check_id=... ile çağrılsa bile çalışır.
    Fazladan parametre gelirse de patlamaz.
    """
    def __init__(
        self,
        id: str = "",
        check_id: str = "",
        title: str = "",
        severity: Any = "LOW",
        resource: str = "",
        why: str = "",
        evidence: Any = None,
        remediation_console: str = "",
        remediation_cli: str = "",
        reference: str = "",
        points: Any = 0,
        service: str = "unknown",
        **kwargs
    ):
        self.id = check_id or id or ""
        self.check_id = self.id  # geriye uyum
        self.title = title
        self.severity = severity
        self.resource = resource
        self.why = why
        self.evidence = evidence
        self.remediation_console = remediation_console
        self.remediation_cli = remediation_cli
        self.reference = reference
        try:
            self.points = int(points or 0)
        except Exception:
            self.points = 0
        self.service = service or "unknown"
        self.extra = kwargs



FindingLike = Union[Finding, Dict[str, Any]]


class ScoringEngine:
    """
    Risk puanı -> güvenlik skoru hesaplar.
    Finding tipi hem dict hem Finding objesi olabilir.
    """

    MAX_SCORE = 100

    # İstersen burayı değiştirilebilir yaparsın ama şimdilik sabit.
    SEVERITY_POINTS = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
    }

    def __init__(self) -> None:
        self.findings: List[FindingLike] = []

    # -----------------------
    # Internal helpers
    # -----------------------
    def _get(self, f: FindingLike, key: str, default: Any = None) -> Any:
        if isinstance(f, dict):
            return f.get(key, default)
        return getattr(f, key, default)

    def _severity(self, f: FindingLike) -> Severity:
        return Severity.normalize(self._get(f, "severity", Severity.LOW))

    def _points(self, f: FindingLike) -> int:
        """
        1) finding içinde points varsa onu kullan
        2) yoksa severity'den puan üret
        """
        p = self._get(f, "points", None)

        # points string gelirse (nadiren) int'e zorla
        if isinstance(p, str):
            p = p.strip()
            if p.isdigit():
                return int(p)

        if isinstance(p, (int, float)):
            return int(p)

        sev = self._severity(f)
        return int(self.SEVERITY_POINTS.get(sev, 0))

    # -----------------------
    # Public API
    # -----------------------
    def add_finding(self, finding: FindingLike) -> None:
        """Bulgu ekle."""
        self.findings.append(finding)

    def calculate_risk_score(self) -> int:
        """
        0-100 arası güvenlik skoru:
        100 - (risk puanları toplamı), min 0
        """
        total_risk_points = sum(self._points(f) for f in self.findings)
        security_score = max(0, self.MAX_SCORE - total_risk_points)
        return int(security_score)

    def get_risk_level(self, score: int) -> Tuple[str, str]:
        """
        Skora göre seviye + renk döner (terminal/rapor için).
        """
        if score >= 80:
            return ("Güvenli", "#4CAF50")
        if score >= 50:
            return ("Orta Risk", "#FFC107")
        return ("Yüksek Risk", "#D32F2F")

    def get_quick_wins(self, limit: int = 5) -> List[FindingLike]:
        """
        En kritik/puanı yüksek bulguları önce döndür.
        """
        def key_fn(f: FindingLike) -> Tuple[int, int]:
            sev = self._severity(f)
            sev_rank = {
                Severity.CRITICAL: 4,
                Severity.HIGH: 3,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
            }.get(sev, 0)
            return (sev_rank, self._points(f))

        sorted_findings = sorted(self.findings, key=key_fn, reverse=True)
        return sorted_findings[: max(0, int(limit))]

    def get_summary(self) -> Dict[str, Any]:
        """
        Bulguların özet istatistiği.
        """
        summary = {
            "total_findings": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total_points": sum(self._points(f) for f in self.findings),
        }

        for f in self.findings:
            sev = self._severity(f)
            if sev == Severity.CRITICAL:
                summary["critical"] += 1
            elif sev == Severity.HIGH:
                summary["high"] += 1
            elif sev == Severity.MEDIUM:
                summary["medium"] += 1
            else:
                summary["low"] += 1

        return summary

    def get_findings_by_severity(self, severity: Union[Severity, str]) -> List[FindingLike]:
        """
        Severity'e göre filtrele.
        """
        target = Severity.normalize(severity)
        return [f for f in self.findings if self._severity(f) == target]

    def get_findings_by_service(self, service: str) -> List[FindingLike]:
        """
        Service adına göre filtrele.
        """
        s = (service or "").strip().lower()
        out: List[FindingLike] = []
        for f in self.findings:
            fs = str(self._get(f, "service", "unknown") or "unknown").strip().lower()
            if fs == s:
                out.append(f)
        return out
