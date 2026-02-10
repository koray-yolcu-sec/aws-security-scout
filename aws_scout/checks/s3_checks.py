"""
S3 Security Checks
Amazon S3 servisi için güvenlik kontrolleri
"""
from botocore.exceptions import ClientError
from ..core.scorer import Finding, Severity


class S3Check:
    """S3 Güvenlik Kontrolleri"""
    
    def __init__(self, s3_client):
        """
        S3 Check başlatıcı
        
        Args:
            s3_client: Boto3 S3 client'ı
        """
        self.s3 = s3_client
        self.findings = []
    
    def run_all_checks(self):
        """
        Tüm S3 kontrollerini çalıştır
        
        Returns:
            list: Finding listesi
        """
        buckets = self._list_buckets()
        
        for bucket in buckets:
            self._check_public_access(bucket)
            self._check_bucket_policy(bucket)
            self._check_encryption(bucket)
            self._check_versioning(bucket)
        
        return self.findings
    
    def _list_buckets(self):
        """
        Tüm S3 bucket'larını listele
        
        Returns:
            list: Bucket isimleri
        """
        try:
            response = self.s3.list_buckets()
            return [bucket['Name'] for bucket in response.get('Buckets', [])]
        except ClientError as e:
            print(f"S3 bucket listeleme hatası: {str(e)}")
            return []
    
    def _check_public_access(self, bucket_name):
        """
        Bucket'ın public access durumunu kontrol et
        
        Args:
            bucket_name: Bucket ismi
        """
        try:
            # Public access block konfigürasyonunu al
            pab_config = self.s3.get_public_access_block(
                Bucket=bucket_name
            )
            
            pab = pab_config['PublicAccessBlockConfiguration']
            
            # Herhangi bir public access açıksa bulgu ekle
            issues = []
            if not pab.get('BlockPublicAcls', True):
                issues.append("Public ACL'ler bloklanmamış")
            if not pab.get('IgnorePublicAcls', True):
                issues.append("Public ACL'ler ignore edilmiyor")
            if not pab.get('BlockPublicPolicy', True):
                issues.append("Public policy'ler bloklanmamış")
            if not pab.get('RestrictPublicBuckets', True):
                issues.append("Public bucket restriction aktif değil")
            
            if issues:
                self.findings.append(Finding(
                    check_id="S3-PUBLIC-ACCESS",
                    resource_id=bucket_name,
                    severity=Severity.HIGH,
                    title="S3 Bucket'ı Public Erişime Açık",
                    description=f"Bucket {bucket_name} için public access kontrolü devre dışı. "
                               f"Bu durum bucket içeriğinin internetten erişilebilir olmasına neden olabilir.",
                    evidence=f"Açık kontroller: {', '.join(issues)}",
                    remedy=self._remedy_public_access(bucket_name),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    service="S3"
                ))
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                # Public access block yapılandırılmamış - bu da risklidir
                self.findings.append(Finding(
                    check_id="S3-PUBLIC-ACCESS",
                    resource_id=bucket_name,
                    severity=Severity.MEDIUM,
                    title="S3 Bucket'ında Public Access Block Yapılandırılmamış",
                    description=f"Bucket {bucket_name} için public access block konfigürasyonu yok. "
                               f"Varsayılan olarak bucket içeriği public olabilir.",
                    evidence="NoSuchPublicAccessBlockConfiguration",
                    remedy=self._remedy_public_access(bucket_name),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    service="S3"
                ))
    
    def _check_bucket_policy(self, bucket_name):
        """
        Bucket policy'sini kontrol et (* wildcard kontrolü)
        
        Args:
            bucket_name: Bucket ismi
        """
        try:
            policy_response = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response['Policy']
            
            # JSON parse edilip * wildcard kontrolü yapılabilir
            # Basit kontrol için string içinde * arıyoruz
            if '"*"' in policy_str or '"*/*"' in policy_str:
                self.findings.append(Finding(
                    check_id="S3-BUCKET-POLICY-WILDCARD",
                    resource_id=bucket_name,
                    severity=Severity.HIGH,
                    title="S3 Bucket Policy'sinde Wildcard (*) İzni Bulundu",
                    description=f"Bucket {bucket_name} policy'sinde '*' wildcard izni var. "
                               f"Bu durum tüm AWS hesaplarına veya tüm IP'lere erişim verilebilir.",
                    evidence="Policy JSON içinde '*' wildcard bulundu",
                    remedy=self._remedy_bucket_policy(bucket_name),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policy-examples.html"
                ))
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                print(f"Bucket policy kontrol hatası ({bucket_name}): {str(e)}")
    
    def _check_encryption(self, bucket_name):
        """
        Bucket encryption durumunu kontrol et
        
        Args:
            bucket_name: Bucket ismi
        """
        try:
            encryption_config = self.s3.get_bucket_encryption(Bucket=bucket_name)
            
            # Encryption konfigürasyonu var mı kontrol et
            rules = encryption_config.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            
            if not rules:
                self.findings.append(Finding(
                    check_id="S3-ENCRYPTION",
                    resource_id=bucket_name,
                    severity=Severity.MEDIUM,
                    title="S3 Bucket'ında Encryption Yapılandırılmamış",
                    description=f"Bucket {bucket_name} için varsayılan encryption yok. "
                               f"Veriler şifrelenmeden saklanıyor.",
                    evidence="ServerSideEncryptionConfiguration boş",
                    remedy=self._remedy_encryption(bucket_name),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
                ))
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                # Encryption yapılandırılmamış
                self.findings.append(Finding(
                    check_id="S3-ENCRYPTION",
                    resource_id=bucket_name,
                    severity=Severity.MEDIUM,
                    title="S3 Bucket'ında Encryption Yapılandırılmamış",
                    description=f"Bucket {bucket_name} için varsayılan encryption yok. "
                               f"Veriler şifrelenmeden saklanıyor.",
                    evidence="ServerSideEncryptionConfiguration bulunamadı",
                    remedy=self._remedy_encryption(bucket_name),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
                ))
    
    def _check_versioning(self, bucket_name):
        """
        Bucket versioning durumunu kontrol et
        
        Args:
            bucket_name: Bucket ismi
        """
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Suspended')
            
            if status != 'Enabled':
                self.findings.append(Finding(
                    check_id="S3-VERSIONING",
                    resource_id=bucket_name,
                    severity=Severity.LOW,
                    title="S3 Bucket'ında Versioning Aktif Değil",
                    description=f"Bucket {bucket_name} için versioning aktif değil. "
                               f"Verilerin yanlışlıkla silinmesi veya üzerine yazılmasına karşı koruma yok.",
                    evidence=f"Versioning Status: {status}",
                    remedy=self._remedy_versioning(bucket_name),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
                ))
                
        except ClientError as e:
            print(f"Versioning kontrol hatası ({bucket_name}): {str(e)}")
    
    def _remedy_public_access(self, bucket_name):
        """Public access düzeltme önerisi"""
        return f"""
**AWS Console:**
1. S3 konsoluna gidin
2. {bucket_name} bucket'ını seçin
3. Permissions sekmesine tıklayın
4. Block public access (bucket settings) kısmında Edit'e tıklayın
5. Tüm kutuları işaretleyin (Block all public access)
6. Save changes'e tıklayın

**AWS CLI:**
```bash
aws s3api put-public-access-block \\
    --bucket {bucket_name} \\
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```
"""
    
    def _remedy_bucket_policy(self, bucket_name):
        """Bucket policy düzeltme önerisi"""
        return f"""
**AWS Console:**
1. S3 konsoluna gidin
2. {bucket_name} bucket'ını seçin
3. Permissions sekmesine tıklayın
4. Bucket Policy bölümünde Edit'e tıklayın
5. Policy'den '*' wildcard'ları kaldırın
6. Save changes'e tıklayın

**AWS CLI:**
```bash
# Önce mevcut policy'i görüntüleyin
aws s3api get-bucket-policy --bucket {bucket_name}

# Sonra policy'i güncelleyin (wildcard'ları kaldırarak)
aws s3api put-bucket-policy \\
    --bucket {bucket_name} \\
    --policy file://updated-policy.json
```
"""
    
    def _remedy_encryption(self, bucket_name):
        """Encryption düzeltme önerisi"""
        return f"""
**AWS Console:**
1. S3 konsoluna gidin
2. {bucket_name} bucket'ını seçin
3. Properties sekmesine tıklayın
4. Default encryption kısmında Edit'e tıklayın
5. SSE-S3 veya SSE-KMS seçin
6. Save changes'e tıklayın

**AWS CLI:**
```bash
# SSE-S3 ile
aws s3api put-bucket-encryption \\
    --bucket {bucket_name} \\
    --server-side-encryption-configuration '{{
        "Rules": [{{
            "ApplyServerSideEncryptionByDefault": {{
                "SSEAlgorithm": "AES256"
            }}
        }}]
    }}'

# Veya SSE-KMS ile
aws s3api put-bucket-encryption \\
    --bucket {bucket_name} \\
    --server-side-encryption-configuration '{{
        "Rules": [{{
            "ApplyServerSideEncryptionByDefault": {{
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "your-kms-key-id"
            }}
        }}]
    }}'
```
"""
    
    def _remedy_versioning(self, bucket_name):
        """Versioning düzeltme önerisi"""
        return f"""
**AWS Console:**
1. S3 konsoluna gidin
2. {bucket_name} bucket'ını seçin
3. Properties sekmesine tıklayın
4. Bucket versioning kısmında Edit'e tıklayın
5. Enable'ı seçin
6. Save changes'e tıklayın

**AWS CLI:**
```bash
aws s3api put-bucket-versioning \\
    --bucket {bucket_name} \\
    --versioning-configuration Status=Enabled
```
"""