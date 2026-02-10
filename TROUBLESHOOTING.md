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
