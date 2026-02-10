"""
Security Score Engine
Bulgu puanlama ve risk hesaplama sistemi
"""


class Severity:
    """Severity seviyeleri ve puanları"""
    CRITICAL = 25
    HIGH = 15
    MEDIUM = 8
    LOW = 3
    
    @classmethod
    def get_name(cls, value):
        """Severity değerine göre isim döndür"""
        mapping = {
            cls.CRITICAL: "Critical",
            cls.HIGH: "High",
            cls.MEDIUM: "Medium",
            cls.LOW: "Low"
        }
        return mapping.get(value, "Unknown")
    
    @classmethod
    def get_color(cls, value):
        """Severity değerine göre renk kodu döndür"""
        mapping = {
            cls.CRITICAL: "#D32F2F",  # Kırmızı
            cls.HIGH: "#F57C00",      # Turuncu
            cls.MEDIUM: "#FBC02D",    # Sarı
            cls.LOW: "#388E3C"        # Yeşil
        }
        return mapping.get(value, "#757575")


class Finding:
    """Güvenlik bulgu sınıfı"""
    
    def __init__(self, check_id, resource_id, severity, title, description, 
                 evidence, remedy, reference=None, service=None):
        """
        Bulgu başlatıcı
        
        Args:
            check_id: Check benzersiz ID'si
            resource_id: Etkilenen kaynak ID'si
            severity: Severity seviyesi (Severity.CRITICAL vb.)
            title: Bulgu başlığı
            description: Bulgu açıklaması
            evidence: Teknik kanıt
            remedy: Düzeltme önerisi
            reference: Referans linki (opsiyonel)
            service: Servis adı (opsiyonel, varsayılan: 'General')
        """
        self.check_id = check_id
        self.resource_id = resource_id
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence
        self.remedy = remedy
        self.reference = reference
        self.service = service if service else 'General'
        self.points = severity  # Bulgu puanı


class ScoringEngine:
    """Skor hesaplama motoru"""
    
    MAX_SCORE = 100
    
    def __init__(self):
        """Skor motoru başlatıcı"""
        self.findings = []
    
    def add_finding(self, finding):
        """
        Bulgu ekle
        
        Args:
            finding: Finding objesi
        """
        self.findings.append(finding)
    
    def calculate_risk_score(self):
        """
        Risk skorunu hesapla
        
        Returns:
            int: 0-100 arası güvenlik skoru
        """
        # Toplam risk puanı (bulguların puanları toplamı)
        total_risk_points = sum(finding.points for finding in self.findings)
        
        # Güvenlik skorunu hesapla (maksimum skordan risk puanını düş)
        # Not: Teorik olarak risk puanı 100'ü aşabilir, bu durumda 0'a düşer
        security_score = max(0, self.MAX_SCORE - total_risk_points)
        
        return security_score
    
    def get_risk_level(self, score):
        """
        Skora göre risk seviyesini belirle
        
        Args:
            score: Güvenlik skoru (0-100)
            
        Returns:
            tuple: (seviye_adı, renk_kodu)
        """
        if score >= 80:
            return ("Güvenli", "#4CAF50")  # Yeşil
        elif score >= 50:
            return ("Orta Risk", "#FFC107")  # Sarı
        else:
            return ("Yüksek Risk", "#D32F2F")  # Kırmızı
    
    def get_quick_wins(self, limit=5):
        """
        En hızlı düzeltilebilecek bulguları listele
        
        Args:
            limit: Maksimum bulgu sayısı
            
        Returns:
            list: Finding listesi (düşük remediation süresi öncelikli)
        """
        # Öncelik: Low severity bulgular önce
        sorted_findings = sorted(
            self.findings,
            key=lambda f: f.severity
        )
        return sorted_findings[:limit]
    
    def get_high_impact_fixes(self, limit=5):
        """
        En çok puan kazandıran düzeltmeleri listele
        
        Args:
            limit: Maksimum bulgu sayısı
            
        Returns:
            list: Finding listesi (yüksek severity öncelikli)
        """
        # Öncelik: High severity bulgular önce
        sorted_findings = sorted(
            self.findings,
            key=lambda f: f.severity,
            reverse=True
        )
        return sorted_findings[:limit]
    
    def get_summary(self):
        """
        Bulgular özetini al
        
        Returns:
            dict: Özet istatistikler
        """
        summary = {
            'total_findings': len(self.findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total_points': sum(f.points for f in self.findings)
        }
        
        for finding in self.findings:
            if finding.severity == Severity.CRITICAL:
                summary['critical'] += 1
            elif finding.severity == Severity.HIGH:
                summary['high'] += 1
            elif finding.severity == Severity.MEDIUM:
                summary['medium'] += 1
            elif finding.severity == Severity.LOW:
                summary['low'] += 1
        
        return summary
    
    def get_findings_by_severity(self, severity):
        """
        Severity'e göre bulguları filtrele
        
        Args:
            severity: Severity değeri
            
        Returns:
            list: Finding listesi
        """
        return [f for f in self.findings if f.severity == severity]