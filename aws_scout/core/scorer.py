# aws_scout/core/scorer.py
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Tuple, Union


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
          - int gibi saçma şeyler gelebilir -> LOW'a düşer
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
    Tek amaç: Repo içindeki farklı check'ler (eski/yeni) hangi formatta bulgu üretirse üretsin,
    raporlayıcı/scorer tarafında PATLAMASIN.

    Desteklenen alanlar (canonical):
      - check_id / id
      - title
      - severity (Severity)
      - resource
      - why
      - evidence
      - remediation_console
      - remediation_cli
      - reference
      - points (int)
      - service
    """

    def __init__(
        self,
        # canonical / yeni
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

        # eski check'ler (compat)
        resource_id: str = "",
        description: str = "",
        remedy: str = "",

        **kwargs: Any,
    ):
        # ID normalize
        self.id = (check_id or id or "").strip()
        self.check_id = self.id  # backward compat

        # Title
        self.title = (title or "").strip()

        # Severity -> enum normalize (KRİTİK fix)
        self.severity: Severity = Severity.normalize(severity)

        # Resource normalize (eski: resource_id)
        self.resource = (resource or resource_id or "").strip()

        # Why normalize (eski: description)
        self.why = (why or description or "").strip()

        # Evidence
        self.evidence = evidence

        # Remediation normalize (eski: remedy)
        self.remediation_console = (remediation_console or "").strip()
        self.remediation_cli = (remediation_cli or "").strip()

        # Eski "remedy" metnini console remediation’a fallback yap
        if not self.remediation_console and remedy:
            self.remediation_console = str(remedy).strip()

        self.reference = (reference or "").strip()

        # Points -> int
        try:
            self.points = int(points or 0)
        except Exception:
            self.points = 0

        # Service normalize
        self.service = (service or "unknown").strip() or "unknown"

        # Extra
        self.extra = kwargs


FindingLike = Union[Finding, Dict[str, Any]]


def as_finding(obj: FindingLike) -> Finding:
    """
    dict -> Finding çevirir
    Finding ise olduğu gibi döner

    Reporter'larda (HTML/MD) loop başında bunu kullanınca:
    'dict' object has no attribute 'severity' biter.
    """
    if isinstance(obj, Finding):
        return obj
    if isinstance(obj, dict):
        return Finding(**obj)
    # ekstrem durum: ne dict ne Finding
    return Finding(title=str(obj), severity="LOW")


class ScoringEngine:
    """
    Risk puanı -> güvenlik skoru hesaplar.
    Finding tipi hem dict hem Finding objesi olabilir.
    """

    MAX_SCORE = 100

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
        # Finding objesinde zaten Severity enum; dict ise normalize
        return Severity.normalize(self._get(f, "severity", Severity.LOW))

    def _points(self, f: FindingLike) -> int:
        """
        1) finding içinde points varsa onu kullan
        2) yoksa severity'den puan üret
        """
        p = self._get(f, "points", None)

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
        self.findings.append(finding)

    def calculate_risk_score(self) -> int:
        total_risk_points = sum(self._points(f) for f in self.findings)
        security_score = max(0, self.MAX_SCORE - total_risk_points)
        return int(security_score)

    def get_risk_level(self, score: int) -> Tuple[str, str]:
        if score >= 80:
            return ("Güvenli", "#4CAF50")
        if score >= 50:
            return ("Orta Risk", "#FFC107")
        return ("Yüksek Risk", "#D32F2F")

    def get_quick_wins(self, limit: int = 5) -> List[FindingLike]:
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
        target = Severity.normalize(severity)
        return [f for f in self.findings if self._severity(f) == target]

    def get_findings_by_service(self, service: str) -> List[FindingLike]:
        s = (service or "").strip().lower()
        out: List[FindingLike] = []
        for f in self.findings:
            fs = str(self._get(f, "service", "unknown") or "unknown").strip().lower()
            if fs == s:
                out.append(f)
        return out
