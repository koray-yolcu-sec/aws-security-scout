"""Terminal Reporter Module
Terminal tabanlı güvenlik raporlama sistemi (TR odaklı)

Bu reporter hem dict finding'leri hem de Finding objelerini destekler.
Beklenen alanlar (dict veya object):
- id / check_id
- title
- severity (Severity enum veya "HIGH" gibi string)
- resource
- why
- evidence
- remediation_console
- remediation_cli
- reference
- points
- service
"""
from typing import List, Dict, Any, Tuple

from ..core.scorer import Severity, Finding


class TerminalReporter:
    """Terminal raporlama sınıfı"""

    # ANSI renk kodları
    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
    }

    # Severity renkleri
    SEVERITY_COLORS = {
        "critical": "\033[91m",  # Kırmızı
        "high": "\033[93m",      # Sarı/Turuncu
        "medium": "\033[95m",    # Mor
        "low": "\033[92m",       # Yeşil
        "unknown": "\033[97m",   # Beyaz
    }

    # Türkçe severity isimleri
    SEVERITY_NAMES = {
        "critical": "KRİTİK",
        "high": "YÜKSEK",
        "medium": "ORTA",
        "low": "DÜŞÜK",
        "unknown": "BİLİNMEYEN",
    }

    def __init__(self, show_details: bool = False, show_summary_only: bool = False):
        """
        Args:
            show_details: Detaylı bulgular gösterilsin mi
            show_summary_only: Sadece özet gösterilsin mi
        """
        self.show_details = show_details
        self.show_summary_only = show_summary_only

    # -------------------------
    # Helpers (dict/object safe)
    # -------------------------
    def _get(self, finding: Any, key: str, default: Any = None) -> Any:
        if isinstance(finding, dict):
            return finding.get(key, default)
        return getattr(finding, key, default)

    def _severity_norm(self, finding: Any) -> Severity:
        sev = self._get(finding, "severity", Severity.LOW)
        if isinstance(sev, Severity):
            return sev
        if isinstance(sev, str):
            s = sev.strip().upper()
            if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return Severity(s)
        return Severity.LOW

    def _points(self, finding: Any) -> int:
        p = self._get(finding, "points", 0)
        try:
            return int(p or 0)
        except Exception:
            return 0

    def _id(self, finding: Any) -> str:
        return str(self._get(finding, "id", "") or self._get(finding, "check_id", "") or "")

    def _title(self, finding: Any) -> str:
        return str(self._get(finding, "title", "") or "")

    def _service(self, finding: Any) -> str:
        return str(self._get(finding, "service", "Bilinmeyen") or "Bilinmeyen")

    def _resource(self, finding: Any) -> str:
        return str(self._get(finding, "resource", "") or "")

    def _why(self, finding: Any) -> str:
        # why alanı yoksa description gibi eski isimlere düş
        return str(
            self._get(finding, "why", "")
            or self._get(finding, "description", "")
            or ""
        )

    def _evidence(self, finding: Any) -> Any:
        return self._get(finding, "evidence", None)

    def _remedy(self, finding: Any) -> str:
        # remediation_console / remediation_cli yoksa remedy'e düş
        console = str(self._get(finding, "remediation_console", "") or "")
        cli = str(self._get(finding, "remediation_cli", "") or "")
        legacy = str(self._get(finding, "remedy", "") or "")

        parts = []
        if console:
            parts.append(f"Console:\n{console}")
        if cli:
            parts.append(f"CLI:\n{cli}")
        if not parts and legacy:
            parts.append(legacy)

        return "\n\n".join(parts).strip()

    def _reference(self, finding: Any) -> str:
        return str(self._get(finding, "reference", "") or "")

    def _severity_key(self, sev: Severity) -> str:
        if sev == Severity.CRITICAL:
            return "critical"
        if sev == Severity.HIGH:
            return "high"
        if sev == Severity.MEDIUM:
            return "medium"
        if sev == Severity.LOW:
            return "low"
        return "unknown"

    # -------------------------
    # Print blocks
    # -------------------------
    def print_header(self):
        print(f"\n{self.COLORS['bold']}{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}")
        print(f"{self.COLORS['bold']}{self.COLORS['cyan']}       AWS Security Scout - Güvenlik Tarama Raporu{self.COLORS['reset']}")
        print(f"{self.COLORS['bold']}{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}\n")

    def print_account_info(self, account_id: str, region: str, score: int):
        print(f"📋 Hesap ID: {account_id}")
        print(f"🌍 Bölge: {region}")

        if score >= 80:
            color = self.COLORS["green"]
            status = "GÜVENLİ"
        elif score >= 50:
            color = self.COLORS["yellow"]
            status = "ORTA RİSK"
        else:
            color = self.COLORS["red"]
            status = "YÜKSEK RİSK"

        print(f"🔒 Güvenlik Skoru: {color}{self.COLORS['bold']}{score}/100{self.COLORS['reset']}")
        print(f"⚠️  Durum: {color}{self.COLORS['bold']}{status}{self.COLORS['reset']}\n")
        print(f"{self.COLORS['cyan']}{'-'*70}{self.COLORS['reset']}\n")

    def print_service_summary(self, service_name: str, findings: List[Any]):
        if not findings:
            return

        icons = {
            "s3": "🪣",
            "iam": "🔑",
            "ec2": "💻",
            "cloudtrail": "📊",
            "logs": "📝",
            "cloudwatch logs": "📝",
            "secrets": "🔐",
            "secretsmanager": "🔐",
            "kms": "🛡️",
        }

        icon = icons.get(service_name.strip().lower(), "📌")

        print(f"\n{self.COLORS['bold']}{icon} {service_name.upper()}{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}{'-'*70}{self.COLORS['reset']}")

        critical = sum(1 for f in findings if self._severity_norm(f) == Severity.CRITICAL)
        high = sum(1 for f in findings if self._severity_norm(f) == Severity.HIGH)
        medium = sum(1 for f in findings if self._severity_norm(f) == Severity.MEDIUM)
        low = sum(1 for f in findings if self._severity_norm(f) == Severity.LOW)
        total_points = sum(self._points(f) for f in findings)

        print(f"   Toplam Bulgu: {len(findings)}")
        print(f"   {self.COLORS['red']}●{self.COLORS['reset']} Kritik: {critical}")
        print(f"   {self.COLORS['yellow']}●{self.COLORS['reset']} Yüksek: {high}")
        print(f"   {self.COLORS['magenta']}●{self.COLORS['reset']} Orta: {medium}")
        print(f"   {self.COLORS['green']}●{self.COLORS['reset']} Düşük: {low}")
        print(f"   💰 Risk Puanı: {total_points}")

    def print_quick_actions(self, findings: List[Any], limit: int = 5):
        if not findings:
            return

        def rank(sev: Severity) -> int:
            return {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}.get(sev, 0)

        sorted_findings = sorted(
            findings,
            key=lambda f: (rank(self._severity_norm(f)), self._points(f)),
            reverse=True
        )[: max(0, int(limit))]

        print(f"\n{self.COLORS['bold']}{self.COLORS['yellow']}⚡ HIZLI AKSİYONLAR (En Öncelikli Düzeltmeler){self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}\n")

        for i, f in enumerate(sorted_findings, 1):
            sev = self._severity_norm(f)
            sev_key = self._severity_key(sev)
            sev_name = self.SEVERITY_NAMES[sev_key]
            sev_color = self.SEVERITY_COLORS[sev_key]

            title = self._title(f)
            resource = self._resource(f)
            why = self._why(f)
            pts = self._points(f)

            print(f"{i}. {self.COLORS['bold']}{title}{self.COLORS['reset']}")
            if resource:
                print(f"   Kaynak: {resource}")
            print(f"   Severity: {sev_color}{sev_name}{self.COLORS['reset']} (+{pts} puan)")

            if why:
                short = (why[:140] + "...") if len(why) > 140 else why
                print(f"   Neden: {short}")
            print()

            if self.show_details:
                remedy = self._remedy(f)
                if remedy:
                    print(f"   {self.COLORS['cyan']}🔧 Düzeltme:{self.COLORS['reset']}")
                    lines = remedy.splitlines()
                    for line in lines[:8]:
                        print(f"   {line}")
                    print()

    def print_detailed_findings(self, findings: List[Any]):
        if not findings or not self.show_details:
            return

        print(f"\n{self.COLORS['bold']}{self.COLORS['blue']}📋 DETAYLI BULGULAR{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}\n")

        for i, f in enumerate(findings, 1):
            sev = self._severity_norm(f)
            sev_key = self._severity_key(sev)
            sev_name = self.SEVERITY_NAMES[sev_key]
            sev_color = self.SEVERITY_COLORS[sev_key]

            print(f"{self.COLORS['bold']}{i}. {self._title(f)}{self.COLORS['reset']}")
            print(f"   {self.COLORS['cyan']}{'─'*70}{self.COLORS['reset']}")
            print(f"   📌 ID: {self._id(f)}")

            resource = self._resource(f)
            if resource:
                print(f"   🎯 Kaynak: {resource}")

            print(f"   ⚠️  Severity: {sev_color}{sev_name}{self.COLORS['reset']} (+{self._points(f)} puan)")

            why = self._why(f)
            if why:
                print(f"   📝 Açıklama: {why}")

            evidence = self._evidence(f)
            if evidence is not None and evidence != "":
                print(f"   🔍 Kanıt: {evidence}")

            remedy = self._remedy(f)
            if remedy:
                print(f"\n   {self.COLORS['green']}🔧 Düzeltme Önerisi:{self.COLORS['reset']}")
                for line in remedy.splitlines():
                    print(f"   {line}")

            ref = self._reference(f)
            if ref:
                print(f"\n   📚 Referans: {ref}")

            print(f"\n{self.COLORS['cyan']}{'─'*70}{self.COLORS['reset']}\n")

    def print_footer(self):
        print(f"\n{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}✓ Rapor oluşturuldu{self.COLORS['reset']}")
        print("👤 Geliştirici: Koray Yolcu (kkyolcu@gmail.com)")
        print("🔗 GitHub: https://github.com/koray-yolcu-sec/aws-security-scout")
        print("⚠️  Bu araç tam READ-ONLY modunda çalışır, AWS kaynaklarınızda değişiklik yapmaz\n")

    def print_error(self, message: str):
        print(f"{self.COLORS['red']}✗ HATA: {message}{self.COLORS['reset']}")

    def generate_report(
        self,
        account_id: str,
        region: str,
        findings: List[Any],
        score: int,
        summary: Dict[str, Any],
    ):
        # Başlık
        self.print_header()

        # Hesap bilgileri
        self.print_account_info(account_id, region, score)

        # Summary only mod
        if self.show_summary_only:
            print(f"\n{self.COLORS['bold']}{self.COLORS['blue']}📊 ÖZET İSTATİSTİKLER{self.COLORS['reset']}")
            print(f"{self.COLORS['cyan']}{'─'*70}{self.COLORS['reset']}\n")
            print(f"Toplam Bulgu: {summary.get('total_findings', len(findings))}")
            print(f"  {self.COLORS['red']}●{self.COLORS['reset']} Kritik: {summary.get('critical', 0)}")
            print(f"  {self.COLORS['yellow']}●{self.COLORS['reset']} Yüksek: {summary.get('high', 0)}")
            print(f"  {self.COLORS['magenta']}●{self.COLORS['reset']} Orta: {summary.get('medium', 0)}")
            print(f"  {self.COLORS['green']}●{self.COLORS['reset']} Düşük: {summary.get('low', 0)}")
            print(f"  💰 Toplam Risk Puanı: {summary.get('total_points', 0)}\n")

            self.print_quick_actions(findings)
            self.print_footer()
            return

        # Servis bazlı grupla
        services: Dict[str, List[Any]] = {}
        for f in findings:
            svc = self._service(f)
            services.setdefault(svc, []).append(f)

        # Her servis için özet
        for service_name, service_findings in services.items():
            self.print_service_summary(service_name, service_findings)

        # Hızlı aksiyonlar
        self.print_quick_actions(findings)

        # Detaylı bulgular
        if self.show_details:
            self.print_detailed_findings(findings)

        # Footer
        self.print_footer()
