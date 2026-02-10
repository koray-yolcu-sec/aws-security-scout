# AWS Security Scout


<div align="center">

**AWS Bulut Güvenlik Misconfiguration Tespit Aracı**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-Read%20Only-orange.svg)](https://aws.amazon.com/)
[![Used in AltaySec Atölye](https://img.shields.io/badge/Used%20in-AltaySec%20Atolye-b91c1c?style=flat-square)](https://atolye.altaysec.com.tr)


</div>

## 🔗 Referans & Kullanım

Bu proje, **AltaySec Atölye** platformunda eğitim ve güvenlik farkındalığı amacıyla kullanılmaktadır.

- **AltaySec Atölye:** https://atolye.altaysec.com.tr  
- **AltaySec Ana Site:** https://altaysec.com.tr


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

