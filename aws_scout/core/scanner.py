"""
Security Scanner Module
Tüm güvenlik kontrollerini koordine eden ana modül
"""
import time
from ..core.aws_auth import AWSAuth
from ..core.scorer import ScoringEngine
from ..core.reporter import Reporter
from ..checks.s3_checks import S3Check
from ..checks.iam_checks import IAMCheck
from ..checks.ec2_checks import EC2Check
from ..checks.cloudtrail_checks import CloudTrailCheck
from ..checks.logging_checks import LoggingCheck
from ..checks.secrets_checks import SecretsCheck
from ..checks.kms_checks import KMSCheck



class SecurityScanner:
    """Ana güvenlik tarayıcı sınıfı"""
    
    def __init__(self, region=None, profile=None, locale='tr'):
        """
        SecurityScanner başlatıcı
        
        Args:
            region: AWS region (opsiyonel)
            profile: AWS CLI profile (opsiyonel)
            locale: Dil kodu ('tr' veya 'en')
        """
        self.auth = AWSAuth(region=region, profile=profile)
        self.scorer = ScoringEngine()
        self.reporter = Reporter(locale=locale)
        self.locale = locale
        self.account_id = None
        self.findings = []
    
    def authenticate(self):
        """AWS kimlik doğrulaması yap"""
        try:
            self.account_id = self.auth.get_account_id()
            print(f"✓ AWS kimlik doğrulaması başarılı")
            print(f"✓ Account ID: {self.account_id}")
            print(f"✓ Region: {self.auth.region}")
            return True
        except Exception as e:
            print(f"✗ AWS kimlik doğrulama hatası: {str(e)}")
            return False
    
    def scan(self, services=None):
        """
        AWS hesabını tara
        
        Args:
            services: Taranacak servislerin listesi (None = tüm servisler)
            
        Returns:
            dict: Tarama sonuçları
        """
        if not self.account_id:
            self.authenticate()
        
        print(f"\\n{'='*60}")
        print(f"AWS Security Scout - Güvenlik Taraması Başlıyor")
        print(f"{'='*60}\\n")
        
        start_time = time.time()
        
        # S3 kontrolleri
        if services is None or 's3' in services:
            print("📦 Amazon S3 kontrol ediliyor...")
            try:
                s3_client = self.auth.get_client('s3')
                s3_check = S3Check(s3_client)
                s3_findings = s3_check.run_all_checks()
                
                for finding in s3_findings:
                    self.scorer.add_finding(finding)
                    self.findings.append(finding)
                
                print(f"   ✓ {len(s3_findings)} bulgu tespit edildi")
            except Exception as e:
                print(f"   ✗ S3 kontrol hatası: {str(e)}")
        
        # IAM kontrolleri
        if services is None or 'iam' in services:
            print("🔐 AWS IAM kontrol ediliyor...")
            try:
                iam_client = self.auth.get_client('iam')
                iam_check = IAMCheck(iam_client)
                iam_findings = iam_check.run_all_checks()
                
                for finding in iam_findings:
                    self.scorer.add_finding(finding)
                    self.findings.append(finding)
                
                print(f"   ✓ {len(iam_findings)} bulgu tespit edildi")
            except Exception as e:
                print(f"   ✗ IAM kontrol hatası: {str(e)}")

                # EC2 kontrolleri
        if services is None or 'ec2' in services:
            print("🖥️ Amazon EC2 kontrol ediliyor...")
            try:
                ec2_client = self.auth.get_client('ec2')
                ec2_check = EC2Check(ec2_client)
                ec2_findings = ec2_check.run_all_checks()
                for f in ec2_findings:
                    self.scorer.add_finding(f)
                    self.findings.append(f)
                print(f"   ✓ {len(ec2_findings)} bulgu tespit edildi")
            except Exception as e:
                print(f"   ✗ EC2 kontrol hatası: {str(e)}")

        # CloudTrail kontrolleri
        if services is None or 'cloudtrail' in services:
            print("🧾 CloudTrail kontrol ediliyor...")
            try:
                ct_client = self.auth.get_client('cloudtrail')
                ct_check = CloudTrailCheck(ct_client)
                ct_findings = ct_check.run_all_checks()
                for f in ct_findings:
                    self.scorer.add_finding(f)
                    self.findings.append(f)
                print(f"   ✓ {len(ct_findings)} bulgu tespit edildi")
            except Exception as e:
                print(f"   ✗ CloudTrail kontrol hatası: {str(e)}")

        # CloudWatch Logs kontrolleri
        if services is None or 'logs' in services or 'cloudwatch logs' in [s.lower() for s in services] if services else []:
            print("📜 CloudWatch Logs kontrol ediliyor...")
            try:
                logs_client = self.auth.get_client('logs')
                logs_check = LoggingCheck(logs_client)
                logs_findings = logs_check.run_all_checks()
                for f in logs_findings:
                    self.scorer.add_finding(f)
                    self.findings.append(f)
                print(f"   ✓ {len(logs_findings)} bulgu tespit edildi")
            except Exception as e:
                print(f"   ✗ Logs kontrol hatası: {str(e)}")

        # Secrets Manager kontrolleri
        if services is None or 'secretsmanager' in services or 'secrets' in services:
            print("🗝️ Secrets Manager kontrol ediliyor...")
            try:
                sm_client = self.auth.get_client('secretsmanager')
                sm_check = SecretsCheck(sm_client)
                sm_findings = sm_check.run_all_checks()
                for f in sm_findings:
                    self.scorer.add_finding(f)
                    self.findings.append(f)
                print(f"   ✓ {len(sm_findings)} bulgu tespit edildi")
            except Exception as e:
                print(f"   ✗ Secrets Manager kontrol hatası: {str(e)}")

        # KMS kontrolleri
        if services is None or 'kms' in services:
            print("🔐 KMS kontrol ediliyor...")
            try:
                kms_client = self.auth.get_client('kms')
                kms_check = KMSCheck(kms_client)
                kms_findings = kms_check.run_all_checks()
                for f in kms_findings:
                    self.scorer.add_finding(f)
                    self.findings.append(f)
                print(f"   ✓ {len(kms_findings)} bulgu tespit edildi")
            except Exception as e:
                print(f"   ✗ KMS kontrol hatası: {str(e)}")

        
        
        # Skor hesapla
        security_score = self.scorer.calculate_risk_score()
        scan_duration = time.time() - start_time
        
        # Sonuçları özetle
        summary = self.scorer.get_summary()
        
        print(f"\\n{'='*60}")
        print(f"Tarama Tamamlandı!")
        print(f"{'='*60}")
        print(f"✓ Süre: {scan_duration:.2f} saniye")
        print(f"✓ Toplam Bulgu: {summary['total_findings']}")
        print(f"  - Critical: {summary['critical']}")
        print(f"  - High: {summary['high']}")
        print(f"  - Medium: {summary['medium']}")
        print(f"  - Low: {summary['low']}")
        print(f"✓ Güvenlik Skoru: {security_score}/100")
        print(f"{'='*60}\\n")
        
        return {
            'account_id': self.account_id,
            'findings': self.findings,
            'score': security_score,
            'summary': summary,
            'duration': scan_duration
        }
    
    def generate_report(self, output_format='md', output_file=None):
        """
        Güvenlik raporu oluştur
        
        Args:
            output_format: Çıktı formatı ('md' veya 'html')
            output_file: Çıktı dosya adı (None = otomatik)
            
        Returns:
            tuple: (report_content, output_file) - Rapor içeriği ve dosya adı
        """
        security_score = self.scorer.calculate_risk_score()
        
        # Dosya adını belirle
        if output_file is None:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            if output_format == 'html':
                output_file = f'aws_scout_report_{self.account_id}_{timestamp}.html'
            else:
                output_file = f'aws_scout_report_{self.account_id}_{timestamp}.md'
        
        # Rapor oluştur
        if output_format == 'html':
            print(f"📄 HTML raporu oluşturuluyor...")
            report_content = self.reporter.generate_html_report(
                self.account_id,
                self.findings,
                security_score,
                output_file
            )
        else:
            print(f"📄 Markdown raporu oluşturuluyor...")
            report_content = self.reporter.generate_markdown_report(
                self.account_id,
                self.findings,
                security_score,
                output_file
            )
        
        print(f"✓ Rapor kaydedildi: {output_file}")
        return report_content, output_file
    
    def get_fix_plan(self):
        """
        Düzeltme planı oluştur
        
        Returns:
            dict: Düzeltme önerileri
        """
        quick_wins = self.scorer.get_quick_wins()
        high_impact = self.scorer.get_high_impact_fixes()
        
        return {
            'quick_wins': quick_wins,
            'high_impact': high_impact
        }
