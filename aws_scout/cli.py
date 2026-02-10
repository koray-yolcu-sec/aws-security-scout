"""
AWS Security Scout - CLI Interface
Kullanıcı dostu komut satırı arayüzü
"""
import argparse
import sys
import traceback
from .core.scanner import SecurityScanner
from .core.terminal_reporter import TerminalReporter


def main():
    """Ana CLI giriş noktası"""
    parser = argparse.ArgumentParser(
        description='AWS Security Scout - AWS Güvenlik Misconfiguration Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Örnekler:
  aws-scout scan                                    # Tüm servisleri tara
  aws-scout scan --services s3 iam                 # Sadece S3 ve IAM'i tara
  aws-scout scan --profile my-profile              # Belirli bir profile kullan
  aws-scout scan --region us-west-2                # Belirli bir region kullan
  aws-scout scan --lang en                         # İngilizce raporla
  aws-scout scan --output terminal                 # Terminal raporu (varsayılan)
  aws-scout scan --output terminal --details       # Terminal detaylı rapor
  aws-scout scan --output terminal --summary       # Terminal özet rapor
  aws-scout scan --output html                     # HTML raporu
  aws-scout scan --output md                       # Markdown raporu
  aws-scout scan --output both                     # Hem HTML hem MD raporu
  aws-scout scan --debug                           # Hata ayıklama modu
        '''
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    # Global options
    parser.add_argument(
        '--profile',
        help='AWS CLI profile adı'
    )
    
    parser.add_argument(
        '--region',
        help='AWS region'
    )
    
    parser.add_argument(
        '--lang',
        choices=['tr', 'en'],
        default='tr',
        help='Rapor dili (varsayılan: tr)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Detaylı hata ayıklama bilgileri göster'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Komutlar')
    
    # Scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='AWS hesabını tara'
    )
    
    scan_parser.add_argument(
        '--services',
        nargs='+',
        choices=['s3', 'iam', 'ec2', 'cloudtrail', 'secrets', 'logs', 'kms'],
        help='Taranacak servisler (varsayılan: tümü)'
    )
    
    scan_parser.add_argument(
        '--output',
        choices=['terminal', 'md', 'html', 'both'],
        default='terminal',
        help='Rapor formatı (varsayılan: terminal)'
    )
    
    scan_parser.add_argument(
        '--details',
        action='store_true',
        help='Terminal modunda detaylı bulgular göster'
    )
    
    scan_parser.add_argument(
        '--summary',
        action='store_true',
        help='Terminal modunda sadece özet göster'
    )
    
    scan_parser.add_argument(
        '--file',
        help='Çıktı dosya adı (varsayılan: otomatik)'
    )
    
    # Report command
    report_parser = subparsers.add_parser(
        'report',
        help='Rapor oluştur'
    )
    
    report_parser.add_argument(
        '--format',
        choices=['md', 'html', 'both'],
        default='md',
        help='Rapor formatı (varsayılan: md)'
    )
    
    report_parser.add_argument(
        '--file',
        help='Çıktı dosya adı (varsayılan: otomatik)'
    )
    
    # Fix-plan command
    fix_parser = subparsers.add_parser(
        'fix-plan',
        help='Düzeltme planı göster'
    )
    
    # Args'ı parse et
    args = parser.parse_args()
    
    # Komut belirtilmediyse help göster
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Hata yönetimi
    try:
        # Scanner'ı başlat
        scanner = SecurityScanner(
            region=args.region,
            profile=args.profile,
            locale=args.lang
        )
    except Exception as e:
        if hasattr(args, 'debug') and args.debug:
            print(f"Scanner başlatma hatası:", file=sys.stderr)
            traceback.print_exc()
        else:
            print(f"Hata: {str(e)}", file=sys.stderr)
        sys.exit(1)
    
    # Komutu çalıştır
    try:
        if args.command == 'scan':
            run_scan(scanner, args)
        elif args.command == 'report':
            run_report(scanner, args)
        elif args.command == 'fix-plan':
            run_fix_plan(scanner, args)
    except KeyboardInterrupt:
        print("\n\n⚠ Tarama kullanıcı tarafından iptal edildi")
        sys.exit(1)
    except Exception as e:
        if hasattr(args, 'debug') and args.debug:
            print(f"\nHata oluştu:", file=sys.stderr)
            traceback.print_exc()
        else:
            print(f"\n✗ Hata: {str(e)}", file=sys.stderr)
        sys.exit(1)


def run_scan(scanner, args):
    """Tarama komutunu çalıştır"""
    # Kimlik doğrulama
    if not scanner.authenticate():
        print("✗ AWS kimlik doğrulaması başarısız")
        sys.exit(1)
    
    # Servis isimlerini düzelt
    services = args.services if hasattr(args, 'services') and args.services else None
    if services:
        # CLI'da 'secrets' ve 'logs' kullanılıyor, scanner'da 'secretsmanager' ve 'logs'
        normalized_services = []
        for service in services:
            if service == 'secrets':
                normalized_services.append('secretsmanager')
            else:
                normalized_services.append(service)
        services = normalized_services
    
    # Tarama yap
    results = scanner.scan(services=services)
    
    # Rapor oluştur
    output_format = args.output
    output_file = args.file if hasattr(args, 'file') and args.file else None
    show_details = hasattr(args, 'details') and args.details
    show_summary = hasattr(args, 'summary') and args.summary
    
    # Terminal raporu
    if output_format == 'terminal':
        terminal_reporter = TerminalReporter(
            show_details=show_details,
            show_summary_only=show_summary
        )
        terminal_reporter.generate_report(
            account_id=results['account_id'],
            region=scanner.auth.region,
            findings=results['findings'],
            score=results['score'],
            summary=results['summary']
        )
    
    # Dosya raporları
    if output_format in ['md', 'html', 'both']:
        if output_format == 'both':
            # Hem MD hem HTML
            scanner.generate_report('md', output_file)
            if output_file:
                html_file = output_file.replace('.md', '.html')
                scanner.generate_report('html', html_file)
            else:
                scanner.generate_report('html')
        else:
            scanner.generate_report(output_format, output_file)
        
        # Sonuç özeti
        print(f"\n✓ Rapor oluşturuldu!")
        print(f"✓ Güvenlik skoru: {results['score']}/100")
        
        if results['score'] >= 80:
            print(f"✓ Durum: Güvenli 🟢")
        elif results['score'] >= 50:
            print(f"⚠ Durum: Orta Risk 🟡")
        else:
            print(f"✗ Durum: Yüksek Risk 🔴")


def run_report(scanner, args):
    """Rapor komutunu çalıştır"""
    # Önce tarayıp bulguları topla (eğer yoksa)
    if not scanner.findings:
        if not scanner.authenticate():
            print("✗ AWS kimlik doğrulaması başarısız")
            sys.exit(1)
        
        scanner.scan()
    
    # Rapor oluştur
    output_format = args.format
    output_file = args.file if hasattr(args, 'file') and args.file else None
    
    if output_format == 'both':
        # Hem MD hem HTML
        scanner.generate_report('md', output_file)
        if output_file:
            html_file = output_file.replace('.md', '.html')
            scanner.generate_report('html', html_file)
        else:
            scanner.generate_report('html')
    else:
        scanner.generate_report(output_format, output_file)
    
    print(f"\n✓ Rapor başarıyla oluşturuldu")


def run_fix_plan(scanner, args):
    """Düzeltme planı komutunu çalıştır"""
    # Önce tarayıp bulguları topla (eğer yoksa)
    if not scanner.findings:
        if not scanner.authenticate():
            print("✗ AWS kimlik doğrulaması başarısız")
            sys.exit(1)
        
        scanner.scan()
    
    # Düzeltme planını al
    fix_plan = scanner.get_fix_plan()
    
    print(f"\n{'='*60}")
    print(f"🔧 Düzeltme Planı")
    print(f"{'='*60}\n")
    
    # Hızlı düzeltmeler
    quick_wins = fix_plan['quick_wins']
    if quick_wins:
        print("🚀 En Hızlı Düzeltilebilecek Bulgular (Öncelik: Low → High)\n")
        for i, finding in enumerate(quick_wins, 1):
            severity_name = TerminalReporter()._get_severity_name(finding.severity)
            print(f"{i}. {finding.title}")
            print(f"   Kaynak: {finding.resource_id}")
            print(f"   Severity: {severity_name}")
            print(f"   Puan: +{finding.points}")
            print()
    else:
        print("✗ Hızlı düzeltilebilecek bulgu yok\n")
    
    print("-" * 60 + "\n")
    
    # Yüksek etki düzeltmeleri
    high_impact = fix_plan['high_impact']
    if high_impact:
        print("📊 En Çok Puan Kazandıran Düzeltmeler (Öncelik: High → Low)\n")
        for i, finding in enumerate(high_impact, 1):
            severity_name = TerminalReporter()._get_severity_name(finding.severity)
            print(f"{i}. {finding.title}")
            print(f"   Kaynak: {finding.resource_id}")
            print(f"   Severity: {severity_name}")
            print(f"   Puan: +{finding.points}")
            print()
    else:
        print("✗ Yüksek etki düzeltmesi yok\n")
    
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()