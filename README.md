# AWS Security Scout


<div align="center">

**AWS Bulut Güvenlik Misconfiguration Tespit Aracı**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-Read%20Only-orange.svg)](https://aws.amazon.com/)

</div>

---

AWS Security Scout, AWS hesaplarında güvenlik yanlış yapılandırmalarını (misconfiguration) tespit eden tam read-only çalışan bir güvenlik tarayıcısıdır. Araç, AWS hesabınızı tarar, kritik güvenlik risklerini belirler ve Türkçe veya İngilizce aksiyon odaklı raporlar sunar.

## Bu Aracı Ne Yapar?

- AWS hesaplarında güvenlik yapılandırma hatalarını tespit eder
- Her bir bulgu için detaylı düzeltme adımları (AWS Console + AWS CLI) sunar
- 100 üzerinden güvenlik skoru hesaplar
- S3, IAM, EC2, CloudTrail, Secrets Manager, KMS servislerini tarar
- Markdown ve HTML formatında raporlar üretir
- Türkçe ve İngilizce rapor desteği sunar
- CI/CD pipeline'lara entegre edilebilir

## Bu Aracı Ne Yapmaz?

- AWS kaynaklarında değişiklik yapmaz (tam read-only)
- Otomatik fix veya silme işlemi yapmaz
- Write/Delete/Modify API'lerini kullanmaz
- Sensitive data saklamaz veya dışarı aktarmaz
- Brute-force veya aktif saldırı yapmaz
- Yasal uyumluluk sertifikasyonu sağlamaz

## Desteklenen AWS Servisleri

### Sürüm 1.0 (MVP)

#### Amazon S3
- Public access kontrolü
- Bucket policy wildcard kontrolü
- Encryption (SSE-S3/SSE-KMS) kontrolü
- Versioning kontrolü

#### AWS IAM
- AdministratorAccess kontrolü
- MFA devre dışı kullanıcılar
- 90+ gün eski access key'ler
- Wildcard (*:*) policy kontrolü

#### Amazon EC2 ve Network
- Security Group 0.0.0.0/0 kontrolü (SSH, RDP, MySQL portları)
- IMDSv1 açık mı kontrolü
- EBS encryption kontrolü

#### Logging ve Audit
- CloudTrail açık mı kontrolü
- Log'ların S3'e gitmesi kontrolü
- Retention policy kontrolü

#### Secrets ve KMS
- Secrets Manager kullanımı kontrolü
- KMS key rotation kontrolü

## Güvenlik Kontrolleri

Araç şu kategorilerde güvenlik kontrolleri gerçekleştirir:

- İdare ve Erişim Yönetimi: MFA kullanımı, access key rotasyonu, overly permissive politikalar
- Veri Koruma: Şifreleme yapılandırması, versiyonlama
- Ağ Güvenliği: Security Group kuralları, açık portlar
- İzleme ve Günlükleme: CloudTrail aktifliği, CloudWatch logları
- Gizli Anahtar Yönetimi: Secrets Manager, KMS key rotation

## Güvenlik Skoru Mantığı

Güvenlik skoru 100 üzerinden hesaplanır ve şu şekilde kategorize edilir:

- 80-100 (Güvenli): Kritik güvenlik açığı bulunamadı, yapılandırma optimal
- 50-79 (Orta Risk): Orta seviye güvenlik riskleri tespit edildi
- 0-49 (Yüksek Risk): Kritik güvenlik açıkları tespit edildi, acil düzeltme gerekli

Skorlama ağırlıkları:
- Critical: 25 puan
- High: 15 puan
- Medium: 8 puan
- Low: 3 puan

## Kurulum

### Önkoşullar
- Python 3.8 veya üzeri
- AWS CLI (opsiyonel)
- AWS hesabı ve IAM yetkileri

### Adım 1: Projeyi İndirin

```bash
git clone https://github.com/koray-yolcu-sec/aws-security-scout.git
cd aws-security-scout
```

### Adım 2: Python Bağımlılıklarını Yükleyin

```bash
python -m pip install -r requirements.txt
```

### Adım 3: AWS Credential'larını Yapılandırın

**Seçenek 1: AWS CLI ile**

```bash
aws configure
```

**Seçenek 2: Environment Variables ile**

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

**Seçenek 3: Belirli Bir Profile ile**

```bash
aws configure --profile my-profile
```

## IAM Yetkileri

Araç tam read-only çalışır. Aşağıdaki IAM policy'si kullanılabilir:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketPolicy",
                "s3:GetBucketAcl",
                "s3:GetPublicAccessBlock",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:ListMFADevices",
                "iam:ListAttachedUserPolicies",
                "iam:ListUserPolicies",
                "iam:GetUserPolicy",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeImages",
                "ec2:DescribeVolumes",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "logs:DescribeLogGroups",
                "secretsmanager:ListSecrets",
                "kms:ListKeys",
                "kms:DescribeKey",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Kullanım Örnekleri

### Temel Tarama (Terminal Raporu)

```bash
python main.py scan
```

**Varsayılan çıktı:** Terminal raporu (özet + hızlı aksiyonlar)

### Detaylı Terminal Raporu

```bash
python main.py scan --output terminal --details
```

Detaylı modda tüm bulguların açıklamaları ve düzeltme adımları gösterilir.

### Sadece Özet Görüntüle

```bash
python main.py scan --output terminal --summary
```

Sadece özet istatistikleri ve hızlı aksiyonları gösterir.

### Belirli Servisleri Tarama

```bash
python main.py scan --services s3 iam
```

### Belirli Region ve Profile ile Tarama

```bash
python main.py scan --profile production --region eu-central-1
```

### HTML Rapor ile Tarama

```bash
python main.py scan --output html
```

### Markdown Rapor ile Tarama

```bash
python main.py scan --output md
```

### Hem Markdown Hem HTML Rapor

```bash
python main.py scan --output both
```

### İngilizce Rapor

```bash
python main.py scan --lang en
```

### Düzeltme Planı Göster

```bash
python main.py fix-plan
```

## Scan Çıktıları Nasıl Görüntülenir?

### ⚠️ Önemli: Terminal-First Yaklaşım

AWS Security Scout **terminal raporunu birincil çıktı** olarak kullanır. Tarama sonuçlarını doğrudan terminalde görebilirsiniz:

```bash
python main.py scan
```

**Terminal Çıktısı İçerir:**
- ✅ Güvenlik skoru ve risk durumu
- ✅ Servis bazlı özet (S3, IAM, EC2, vb.)
- ✅ Her servis için bulgu sayısı ve dağılımı
- ✅ "Hızlı Aksiyonlar" bölümü (en öncelikli düzeltmeler)
- ✅ Toplam risk puanları

### Çıktı Formatları

AWS Security Scout 4 farklı çıktı formatı sunar:

#### 1. Terminal Raporu (Varsayılan)
```bash
python main.py scan
# Veya
python main.py scan --output terminal
```

- Hızlı ve doğrudan terminalde görünür
- Özet ve hızlı aksiyonları gösterir
- Detaylı mod (`--details`) ile tam bulguları gösterir
- Özet mod (`--summary`) ile sadece özeti gösterir

#### 2. Detaylı Terminal Raporu
```bash
python main.py scan --output terminal --details
```

Tüm bulguların detayları, açıklamaları ve düzeltme adımları terminalde gösterilir.

#### 3. Sadece Özet (Quick Wins)
```bash
python main.py scan --output terminal --summary
```

Sadece özet istatistikleri ve hızlı aksiyonları gösterir.

#### 4. HTML Rapor
```bash
python main.py scan --output html
```

- İnteraktif HTML raporu oluşturur
- Detaylı analiz için ideal
- Tarayıcıda açılabilir

#### 5. Markdown Rapor
```bash
python main.py scan --output md
```

- Markdown formatında rapor
- GitHub, GitLab vb. platformlarda paylaşılabilir

#### 6. Hem HTML Hem Markdown
```bash
python main.py scan --output both
```

Her iki format da oluşturulur.

### Terminal Raporu Örneği

```
======================================================================
       AWS Security Scout - Güvenlik Tarama Raporu
======================================================================

📋 Hesap ID: 123456789012
🌍 Bölge: eu-north-1
🔒 Güvenlik Skoru: 65/100
⚠️  Durum: ORTA RISK

----------------------------------------------------------------------

🪣 S3
----------------------------------------------------------------------
   Toplam Bulgu: 5
   ● Kritik: 1
   ● Yüksek: 2
   ● Orta: 1
   ● Düşük: 1
   💰 Risk Puanı: 56

⚡ HIZLI AKSİYONLAR (En Öncelikli Düzeltmeler)
======================================================================

1. S3 Bucket'ı Public Erişime Açık
   Kaynak: my-bucket
   Severity: KRİTİK (+25 puan)
   Neden: Bucket my-bucket için public access kontrolü devre dışı...
   
   🔧 Düzeltme:
   **AWS Console:**
   1. S3 konsoluna gidin
   2. my-bucket bucket'ını seçin
   ...

======================================================================
✓ Rapor oluşturuldu
👤 Geliştirici: Koray Yolcu (kkyolcu@gmail.com)
🔗 GitHub: https://github.com/koray-yolcu-sec/aws-security-scout
⚠️  Bu araç tam READ-ONLY modunda çalışır, AWS kaynaklarınızda değişiklik yapmaz
```

### Neden Terminal Raporu?

Terminal raporu şu avantajları sunar:

- ✅ **Hızlı**: Dosya açmaya gerek yok, anında görünür
- ✅ **Kopyalanabilir**: Düzeltme komutlarını doğrudan kopyalayabilirsiniz
- ✅ **Aramalı**: Tüm bulgular tek ekranda
- ✅ **Script Friendly**: CI/CD pipeline'larına entegre edilebilir
- ✅ **ANSI Renkleri**: Okunabilirlik için renklendirme

### İleri Kullanım: Terminal + Dosya

Hem terminal raporu hem de dosya raporu alabilirsiniz:

```bash
# Terminal raporunu görüntüle
python main.py scan

# Sonra detaylı HTML raporu oluştur
python main.py scan --output html

# Veya tek komutla her ikisi (terminal + HTML)
python main.py scan --output html
```

**Not:** Terminal raporu her zaman gösterilir, `--output` parametresi sadece dosya çıktısını etkiler.<timestamp>.html` - İnteraktif HTML rapor
- `security_report_<timestamp>.md` - Markdown formatında rapor

Dosyalar, taramayı çalıştırdığınız dizinde oluşturulur. `<timestamp>` kısmı tarama zamanını temsil eder (örneğin: `security_report_20240315_143022.html`).

### Raporu Tarayıcıda Açma

#### macOS

```bash
open security_report_*.html
```

#### Linux

```bash
xdg-open security_report_*.html
```

#### Windows

Windows'ta iki yöntemle raporu açabilirsiniz:

**Yöntem 1: PowerShell ile**
```powershell
Start-Process security_report_*.html
```

**Yöntem 2: Windows Gezgini**
1. Oluşturulan `security_report_*.html` dosyasını bulun
2. Dosyaya çift tıklayın veya sağ tıklayıp "Aç" seçeneğini kullanın

### Neden HTML Raporu Tercih Edilmeli?

HTML raporu terminal çıktısına göre şu avantajları sunar:

- ✅ **İnteraktif Navigasyon**: Başlıklar arasında hızlı gezinme
- ✅ **Görsel Hiyerarşi**: Severity bazlı renklendirme (Critical = Kırmızı, High = Turuncu, vb.)
- ✅ **Kopyalanabilir Kod**: Düzeltme komutlarını tek tıkla kopyalama
- ✅ **Detaylı Açıklamalar**: Her bulgu için teknik kanıtlar ve AWS Best Practice referansları
- ✅ **Responsive Tasarım**: Mobil ve masaüstü tarayıcılarda düzgün görüntülenme

### Örnek İş Akışı

```bash
# 1. Taramayı başlatın
python main.py scan

# Çıktı:
# AWS Security Scout v1.0.0
# GÜVENLİK SKORU: 65/100 (Orta Risk)
# Rapor oluşturuldu: security_report_20240315_143022.html

# 2. Raporu tarayıcıda açın (macOS örneği)
open security_report_20240315_143022.html
```

**Not**: Terminal çıktısında rapor dosyasının tam yolu belirtilir. Bu yolu kullanarak rapora hızlıca erişebilirsiniz.

## Örnek Çıktı

### Konsol Çıktısı

```
AWS Security Scout v1.0.0
Taranan Bölge: eu-central-1
Taranan Servisler: S3, IAM, EC2, CloudTrail

GÜVENLİK SKORU: 72/100 (Orta Risk)

BULGULAR:
Critical: 2
High: 5
Medium: 8
Low: 3

HIZLI DÜZELTMELER (Quick Wins):
1. [LOW] S3 bucket encryption aktif et
2. [LOW] IAM kullanıcısına MFA etkinleştir
3. [LOW] CloudTrail log retention artır

YÜKSEK ETKİ DÜZELTMELERİ (High Impact):
1. [CRITICAL] S3 bucket public erişimini kapat
2. [CRITICAL] Security Group 0.0.0.0/0 SSH erişimini kapat
3. [HIGH] AdministratorAccess politikasını kaldır

Rapor oluşturuldu: security_report_20240315_143022.html
```

### Markdown Rapor Yapısı

Rapor şu bölümleri içerir:

- Rapor Başlığı: Oluşturulma tarihi, AWS hesap ID, güvenlik skoru, risk durumu
- Özet Tablosu: Critical, High, Medium, Low bulgu sayıları, toplam bulgu sayısı
- Hızlı Düzeltmeler (Quick Wins): En kolay çözülebilecek 5 bulgu
- Yüksek Etki Düzeltmeleri (High Impact): En çok puan kazandıran 5 bulgu
- Detaylı Bulgular: Her bulgu için ID, başlık, severity, etkilenen kaynak, neden önemli, teknik kanıt, düzeltme önerisi (AWS Console + AWS CLI), AWS Best Practice referansı


## Proje Mimarisi

```
aws-security-scout/
├── main.py                    # CLI giriş noktası (python main.py ...)
├── aws_scout/                 # Ana uygulama paketi
│   ├── __init__.py
│   ├── cli.py                 # Argparse / CLI yönlendirme
│   ├── core/                  # Çekirdek mantık
│   │   ├── __init__.py
│   │   ├── aws_auth.py        # AWS kimlik doğrulama
│   │   ├── scanner.py         # Tarama motoru
│   │   ├── scorer.py          # Güvenlik skoru hesaplama
│   │   └── reporter.py        # Rapor üretimi (MD / HTML)
│   ├── checks/                # Servis bazlı güvenlik kontrolleri
│   │   ├── __init__.py
│   │   ├── s3_checks.py       # S3 kontrolleri
│   │   ├── iam_checks.py      # IAM kontrolleri
│   │   ├── ec2_checks.py      # EC2 kontrolleri
│   │   └── logging_checks.py  # Logging kontrolleri
│   ├── locales/               
│   │   ├── tr.json            # Türkçe çeviri
│   │   └── en.json            # İngilizce çeviri
│   └── templates/             # Rapor şablonları
├── docs/                      # Dokümantasyon
│   ├── ARCHITECTURE.md
│   └── CHECKS.md
├── example_report.md          # Örnek çıktı
├── requirements.txt           # Python bağımlılıkları
└── README.md                  # Proje dokümantasyonu
```

Mimari prensipleri:
- Modüler ve genişletilebilir yapı
- Her servis için ayrı kontrol modülü
- Read-only erişim ile güvenli tarama
- Çoklu dil desteği (Türkçe ve İngilizce)

## Güvenlik ve Legal

Bu araç:
- Tam read-only API'ler kullanır
- AWS Best Practices'e uygun çalışır
- Legal ve etik sınırlar içinde kalır
- Müşteri verilerini gizli tutar
- Detaylı audit log tutar

Yasal uyarı:
- Bu araç AWS kaynaklarını okumakla sınırlıdır. Kaynak oluşturma, silme veya değiştirme işlemleri yapmaz.
- Tarama sonuçları yerel ortamınızda saklanır. Veriler harici bir servise gönderilmez.
- Bu araç yasal uyumluluk sertifikasyonu sağlamaz. SOC2, ISO27001, PCI-DSS gibi sertifikasyonlar için ek denetimler gerekir.
- Kullanımınızdan kaynaklanan veri kaybından, iş kesintisinden veya diğer zararlardan aracı geliştiricileri sorumlu değildir.

## Bu Araç Kimler İçin Uygun?

### Uygun Kullanıcılar
- Cloud Security Engineer / Analyst
- DevOps Engineer
- Site Reliability Engineer (SRE)
- AWS Sertifika adayları
- Güvenlik öğrenmek isteyen öğrenciler
- KOBİ IT yöneticileri

### Uygun Olmayan Kullanıcılar
- AWS temel bilgisi olmayan kullanıcılar
- Otomatik remediation aracı arayanlar
- Gerçek zamanlı tehdit algılama çözümü arayanlar
- Enterprise seviye SIEM çözümü arayanlar

## Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Fork bu repository
2. Feature branch oluştur: `git checkout -b feature/amazing-feature`
3. Değişikliklerini yap ve test et
4. Commit yap: `git commit -m 'Add amazing feature'`
5. Branch'i push et: `git push origin feature/amazing-feature`
6. Pull Request aç

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.


## Sorun Giderme (Troubleshooting)

### Yaygın Sorunlar ve Çözümleri

#### AWS Kimlik Doğrulama Hatası
**Sorun:** `AWS kimlik doğrulaması başarısız` hatası alıyorum.

**Çözümler:**
1. AWS CLI'nin doğru yapılandırıldığından emin olun:
   ```bash
   aws configure list
   ```
2. Environment variables'ları kontrol edin:
   ```bash
   echo $AWS_ACCESS_KEY_ID
   echo $AWS_SECRET_ACCESS_KEY
   echo $AWS_DEFAULT_REGION
   ```
3. Credential dosyasını kontrol edin (`~/.aws/credentials`):
   ```ini
   [default]
   aws_access_key_id = YOUR_ACCESS_KEY
   aws_secret_access_key = YOUR_SECRET_KEY
   ```
4. `--profile` parametresi ile belirli bir profile deneyin:
   ```bash
   python main.py scan --profile my-profile
   ```

#### Modül Bulunamadı Hatası
**Sorun:** `ModuleNotFoundError: No module named 'boto3'` hatası alıyorum.

**Çözüm:**
Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
# Veya
pip install boto3 botocore jinja2
```

#### Permission Hatası
**Sorun:** AWS API çağrılarında "AccessDenied" hatası alıyorum.

**Çözüm:**
1. IAM kullanıcınızın gerekli izinlere sahip olduğundan emin olun
2. README'deki IAM policy'sini kullanıcınıza ekleyin
3. `iam_readonly_policy.json` dosyasını kullanarak policy oluşturabilirsiniz:
   ```bash
   aws iam put-user-policy --user-name USERNAME --policy-name AWS-Security-Scout --policy-document file://iam_readonly_policy.json
   ```

#### Terminal Raporu Çıkmıyor
**Sorun:** `--output terminal` flag'i çalışmıyor.

**Çözüm:**
Terminal raporu varsayılan olarak aktiftir, flag'i belirtmenize gerek yoktur:
```bash
python main.py scan
```

Detaylı rapor için:
```bash
python main.py scan --output terminal --details
```

Sadece özet için:
```bash
python main.py scan --output terminal --summary
```

#### Rapor Dosyası Oluşturmuyor
**Sorun:** HTML/MD raporu oluşturulmuyor.

**Çözüm:**
Çıktı formatını belirtin:
```bash
# HTML raporu
python main.py scan --output html

# Markdown raporu
python main.py scan --output md

# Her ikisi
python main.py scan --output both
```

#### Hata Ayıklama Modu
**Sorun:** Detaylı hata mesajlarını görmek istiyorum.

**Çözüm:**
`--debug` flag'ini kullanın:
```bash
python main.py scan --debug
```

Bu modda tam stack trace göreceksiniz.

#### Sadece Belirli Servisleri Taramak İstiyorum
**Çözüm:**
`--services` parametresi ile servisi belirtin:
```bash
python main.py scan --services s3 iam
```

Desteklenen servisler: `s3`, `iam`, `ec2`, `cloudtrail`, `logs`, `secrets`, `kms`

#### Bölge (Region) Belirtme
**Çözüm:**
`--region` parametresi ile bölge belirtin:
```bash
python main.py scan --region eu-north-1
```

#### Hızlı Aksiyonlar Görmek İstiyorum
**Çözüm:**
Özet modunu kullanın:
```bash
python main.py scan --output terminal --summary
```

Bu modda sadece özet ve hızlı aksiyonlar gösterilir.

### Log Dosyaları ve Debug

Hata ayıklama için `--debug` flag'i kullanabilirsiniz. Bu modda:
- Tam stack trace gösterilir
- Detaylı hata mesajları yazdırılır
- AWS API hataları detaylı görüntülenir

### Destek Alın

Sorununuz burada çözülemezse:
1. [GitHub Issues](https://github.com/koray-yolcu-sec/aws-security-scout/issues) sayfasında arama yapın
2. Yeni issue açarken şunları ekleyin:
   - Hata mesajı (tam çıktı)
   - Kullandığınız komut
   - Python sürümü (`python --version`)
   - AWS bölgesi
   - `--debug` flag'i ile aldığınız detaylı çıktı

3. Email: kkyolcu@gmail.com

## İletişim ve Destek

- Sorular: [GitHub Issues](https://github.com/kkyolcu/aws-security-scout/issues)
- Özellik istekleri: [GitHub Issues](https://github.com/kkyolcu/aws-security-scout/issues)
- Email: kkyolcu@gmail.com


## 👨‍💻 Yapımcı

**Koray Yolcu** — kkyolcu@gmail.com

---

<div align="center">

**⭐ Eğer projeyi beğendiyseniz, lütfen yıldız vermeyi unutmayın!**

Made with ❤️ by Koray Yolcu

</div>

