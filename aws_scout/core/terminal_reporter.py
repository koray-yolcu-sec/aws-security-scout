"""Terminal Reporter Module
Terminal tabanlı güvenlik raporlama sistemi
"""
from ..core.scorer import Severity, Finding
from typing import List, Dict, Any


class TerminalReporter:
    """Terminal raporlama sınıfı"""
    
    # ANSI renk kodları
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    
    # Severity renkleri
    SEVERITY_COLORS = {
        'critical': '\033[91m',  # Kırmızı
        'high': '\033[93m',      # Sarı/Turuncu
        'medium': '\033[95m',    # Mor
        'low': '\033[92m',       # Yeşil
    }
    
    # Türkçe severity isimleri
    SEVERITY_NAMES = {
        'critical': 'KRİTİK',
        'high': 'YÜKSEK',
        'medium': 'ORTA',
        'low': 'DÜŞÜK',
    }
    
    def __init__(self, show_details=False, show_summary_only=False):
        """
        Terminal Reporter başlatıcı
        
        Args:
            show_details: Detaylı bulgular gösterilsin mi
            show_summary_only: Sadece özet gösterilsin mi
        """
        self.show_details = show_details
        self.show_summary_only = show_summary_only
    
    def print_header(self):
        """Rapor başlığını yazdır"""
        print(f"\n{self.COLORS['bold']}{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}")
        print(f"{self.COLORS['bold']}{self.COLORS['cyan']}       AWS Security Scout - Güvenlik Tarama Raporu{self.COLORS['reset']}")
        print(f"{self.COLORS['bold']}{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}\n")
    
    def print_account_info(self, account_id: str, region: str, score: int):
        """
        Hesap bilgilerini yazdır
        
        Args:
            account_id: AWS hesap ID'si
            region: AWS bölgesi
            score: Güvenlik skoru
        """
        print(f"📋 Hesap ID: {account_id}")
        print(f"🌍 Bölge: {region}")
        
        # Skoru renklendir
        if score >= 80:
            color = self.COLORS['green']
            status = "GÜVENLİ"
        elif score >= 50:
            color = self.COLORS['yellow']
            status = "ORTA RİSK"
        else:
            color = self.COLORS['red']
            status = "YÜKSEK RİSK"
        
        print(f"🔒 Güvenlik Skoru: {color}{self.COLORS['bold']}{score}/100{self.COLORS['reset']}")
        print(f"⚠️  Durum: {color}{self.COLORS['bold']}{status}{self.COLORS['reset']}\n")
        print(f"{self.COLORS['cyan']}{'-'*70}{self.COLORS['reset']}\n")
    
    def print_service_summary(self, service_name: str, findings: List[Finding]):
        """
        Servis bazlı özeti yazdır
        
        Args:
            service_name: Servis adı
            findings: Bulgu listesi
        """
        if not findings:
            return
        
        # Servis ikonu
        icons = {
            's3': '🪣',
            'iam': '🔑',
            'ec2': '💻',
            'cloudtrail': '📊',
            'cloudwatch logs': '📝',
            'secretsmanager': '🔐',
            'kms': '🛡️',
        }
        icon = icons.get(service_name.lower(), '📌')
        
        print(f"\n{self.COLORS['bold']}{icon} {service_name.upper()}{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}{'-'*70}{self.COLORS['reset']}")
        
        # İstatistikler
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        total_points = sum(f.points for f in findings)
        
        print(f"   Toplam Bulgu: {len(findings)}")
        print(f"   {self.COLORS['red']}●{self.COLORS['reset']} Kritik: {critical}")
        print(f"   {self.COLORS['yellow']}●{self.COLORS['reset']} Yüksek: {high}")
        print(f"   {self.COLORS['magenta']}●{self.COLORS['reset']} Orta: {medium}")
        print(f"   {self.COLORS['green']}●{self.COLORS['reset']} Düşük: {low}")
        print(f"   💰 Risk Puanı: {total_points}")
    
    def print_quick_actions(self, findings: List[Finding], limit=5):
        """
        Hızlı aksiyonlar bölümünü yazdır
        
        Args:
            findings: Bulgu listesi
            limit: Maksimum bulgu sayısı
        """
        if not findings:
            return
        
        # En yüksek öncelikli bulguları al (severity'e göre sırala)
        sorted_findings = sorted(
            findings,
            key=lambda f: f.severity,
            reverse=True
        )[:limit]
        
        print(f"\n{self.COLORS['bold']}{self.COLORS['yellow']}⚡ HIZLI AKSİYONLAR (En Öncelikli Düzeltmeler){self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}\n")
        
        for i, finding in enumerate(sorted_findings, 1):
            severity_name = self._get_severity_name(finding.severity)
            severity_color = self._get_severity_color(finding.severity)
            
            print(f"{i}. {self.COLORS['bold']}{finding.title}{self.COLORS['reset']}")
            print(f"   Kaynak: {finding.resource_id}")
            print(f"   Severity: {severity_color}{severity_name}{self.COLORS['reset']} (+{finding.points} puan)")
            print(f"   Neden: {finding.description[:100]}...")
            print()
            
            # Düzeltme önerisi
            if self.show_details:
                print(f"   {self.COLORS['cyan']}🔧 Düzeltme:{self.COLORS['reset']}")
                remedy_lines = finding.remedy.strip().split('\n')
                for line in remedy_lines[:5]:  # İlk 5 satır
                    print(f"   {line}")
                print()
    
    def print_detailed_findings(self, findings: List[Finding]):
        """
        Detaylı bulguları yazdır
        
        Args:
            findings: Bulgu listesi
        """
        if not findings or not self.show_details:
            return
        
        print(f"\n{self.COLORS['bold']}{self.COLORS['blue']}📋 DETAYLI BULGULAR{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}\n")
        
        for i, finding in enumerate(findings, 1):
            severity_name = self._get_severity_name(finding.severity)
            severity_color = self._get_severity_color(finding.severity)
            
            print(f"{self.COLORS['bold']}{i}. {finding.title}{self.COLORS['reset']}")
            print(f"   {self.COLORS['cyan']}{'─'*70}{self.COLORS['reset']}")
            print(f"   📌 ID: {finding.check_id}")
            print(f"   🎯 Kaynak: {finding.resource_id}")
            print(f"   ⚠️  Severity: {severity_color}{severity_name}{self.COLORS['reset']} (+{finding.points} puan)")
            print(f"   📝 Açıklama: {finding.description}")
            print(f"   🔍 Kanıt: {finding.evidence}")
            print(f"\n   {self.COLORS['green']}🔧 Düzeltme Önerisi:{self.COLORS['reset']}")
            print(f"   {finding.remedy}")
            
            if finding.reference:
                print(f"\n   📚 Referans: {finding.reference}")
            
            print(f"\n{self.COLORS['cyan']}{'─'*70}{self.COLORS['reset']}\n")
    
    def print_footer(self):
        """Rapor footer'ını yazdır"""
        print(f"\n{self.COLORS['cyan']}{'='*70}{self.COLORS['reset']}")
        print(f"{self.COLORS['cyan']}✓ Rapor oluşturuldu{self.COLORS['reset']}")
        print(f"👤 Geliştirici: Koray Yolcu (kkyolcu@gmail.com)")
        print(f"🔗 GitHub: https://github.com/koray-yolcu-sec/aws-security-scout")
        print(f"⚠️  Bu araç tam READ-ONLY modunda çalışır, AWS kaynaklarınızda değişiklik yapmaz\n")
    
    def print_error(self, message: str):
        """Hata mesajı yazdır"""
        print(f"{self.COLORS['red']}✗ HATA: {message}{self.COLORS['reset']}", file=None)
    
    def print_success(self, message: str):
        """Başarı mesajı yazdır"""
        print(f"{self.COLORS['green']}✓ {message}{self.COLORS['reset']}")
    
    def print_info(self, message: str):
        """Bilgi mesajı yazdır"""
        print(f"{self.COLORS['cyan']}ℹ {message}{self.COLORS['reset']}")
    
    def print_warning(self, message: str):
        """Uyarı mesajı yazdır"""
        print(f"{self.COLORS['yellow']}⚠ {message}{self.COLORS['reset']}")
    
    def _get_severity_name(self, severity_value: int) -> str:
        """Severity değerine göre Türkçe isim döndür"""
        if severity_value == Severity.CRITICAL:
            return self.SEVERITY_NAMES['critical']
        elif severity_value == Severity.HIGH:
            return self.SEVERITY_NAMES['high']
        elif severity_value == Severity.MEDIUM:
            return self.SEVERITY_NAMES['medium']
        elif severity_value == Severity.LOW:
            return self.SEVERITY_NAMES['low']
        else:
            return 'BİLİNMEYEN'
    
    def _get_severity_color(self, severity_value: int) -> str:
        """Severity değerine göre renk kodu döndür"""
        if severity_value == Severity.CRITICAL:
            return self.SEVERITY_COLORS['critical']
        elif severity_value == Severity.HIGH:
            return self.SEVERITY_COLORS['high']
        elif severity_value == Severity.MEDIUM:
            return self.SEVERITY_COLORS['medium']
        elif severity_value == Severity.LOW:
            return self.SEVERITY_COLORS['low']
        else:
            return self.COLORS['white']
    
    def generate_report(
        self,
        account_id: str,
        region: str,
        findings: List[Finding],
        score: int,
        summary: Dict[str, Any]
    ):
        """
        Komple terminal raporu oluştur
        
        Args:
            account_id: AWS hesap ID'si
            region: AWS bölgesi
            findings: Bulgu listesi
            score: Güvenlik skoru
            summary: Özet istatistikler
        """
        # Başlık
        self.print_header()
        
        # Hesap bilgileri
        self.print_account_info(account_id, region, score)
        
        if not self.show_summary_only:
            # Servis bazlı özet
            services = {}
            for finding in findings:
                service = getattr(finding, 'service', 'Bilinmeyen')
                if service not in services:
                    services[service] = []
                services[service].append(finding)
            
            # Her servis için özet yazdır
            for service_name, service_findings in services.items():
                self.print_service_summary(service_name, service_findings)
            
            # Hızlı aksiyonlar
            self.print_quick_actions(findings)
            
            # Detaylı bulgular (eğer istenmişse)
            if self.show_details:
                self.print_detailed_findings(findings)
        else:
            # Sadece özet modu
            print(f"\n{self.COLORS['bold']}{self.COLORS['blue']}📊 ÖZET İSTATİSTİKLER{self.COLORS['reset']}")
            print(f"{self.COLORS['cyan']}{'─'*70}{self.COLORS['reset']}\n")
            print(f"Toplam Bulgu: {summary['total_findings']}")
            print(f"  {self.COLORS['red']}●{self.COLORS['reset']} Kritik: {summary['critical']}")
            print(f"  {self.COLORS['yellow']}●{self.COLORS['reset']} Yüksek: {summary['high']}")
            print(f"  {self.COLORS['magenta']}●{self.COLORS['reset']} Orta: {summary['medium']}")
            print(f"  {self.COLORS['green']}●{self.COLORS['reset']} Düşük: {summary['low']}")
            print(f"  💰 Toplam Risk Puanı: {summary['total_points']}\n")
            
            # Hızlı aksiyonlar
            self.print_quick_actions(findings)
        
        # Footer
        self.print_footer()