"""
AWS Authentication Module
AWS Credential yönetimi ve session işlemleri
"""
import boto3
from botocore.exceptions import NoCredentialsError, ClientError


class AWSAuth:
    """AWS authentication ve session yönetimi"""
    
    def __init__(self, region=None, profile=None):
        """
        AWS Auth başlatıcı
        
        Args:
            region: AWS region (opsiyonel)
            profile: AWS CLI profile (opsiyonel)
        """
        self.region = region
        self.profile = profile
        self.session = None
        self.account_id = None
        self._initialize_session()
    
    def _initialize_session(self):
        """Boto3 session oluştur"""
        session_kwargs = {}
        
        if self.profile:
            session_kwargs['profile_name'] = self.profile
        
        self.session = boto3.Session(**session_kwargs)
        
        # Region belirle
        if not self.region:
            self.region = self.session.region_name or 'us-east-1'
    
    def get_client(self, service):
        """
        AWS service client'ı oluştur
        
        Args:
            service: AWS servis adı (ör: 's3', 'iam', 'ec2')
            
        Returns:
            boto3 client
        """
        return self.session.client(service, region_name=self.region)
    
    def get_account_id(self):
        """
        AWS Account ID'yi al
        
        Returns:
            str: Account ID
        """
        if not self.account_id:
            try:
                sts = self.get_client('sts')
                response = sts.get_caller_identity()
                self.account_id = response['Account']
            except (NoCredentialsError, ClientError) as e:
                raise Exception(f"AWS kimlik doğrulama hatası: {str(e)}")
        
        return self.account_id
    
    def verify_readonly_access(self):
        """
        Read-only yetkiyi kontrol et
        
        Returns:
            bool: Read-only yetki var mı?
        """
        try:
            iam = self.get_client('iam')
            # Test için basit bir IAM sorgusu yap
            iam.list_roles(MaxItems=1)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                return False
            raise
    
    def get_available_regions(self, service):
        """
        Servisin mevcut bölgelerini al
        
        Args:
            service: AWS servis adı
            
        Returns:
            list: Bölge listesi
        """
        try:
            regions = self.session.get_available_regions(service)
            return regions if regions else [self.region]
        except Exception:
            return [self.region]