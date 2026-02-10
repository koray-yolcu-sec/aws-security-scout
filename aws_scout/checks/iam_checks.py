"""
IAM Security Checks
AWS IAM servisi için güvenlik kontrolleri
"""
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from ..core.scorer import Finding, Severity


class IAMCheck:
    """IAM Güvenlik Kontrolleri"""
    
    def __init__(self, iam_client):
        """
        IAM Check başlatıcı
        
        Args:
            iam_client: Boto3 IAM client'ı
        """
        self.iam = iam_client
        self.findings = []
    
    def run_all_checks(self):
        """
        Tüm IAM kontrollerini çalıştır
        
        Returns:
            list: Finding listesi
        """
        self._check_admin_users()
        self._check_mfa_disabled_users()
        self._check_old_access_keys()
        self._check_wildcard_policies()
        
        return self.findings
    
    def _check_admin_users(self):
        """AdministratorAccess policy'sine sahip kullanıcıları kontrol et"""
        try:
            # Tüm kullanıcıları listele
            users = []
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            # Tüm attached user policies'leri kontrol et
            admin_users = []
            for user in users:
                user_name = user['UserName']
                
                # Attached policies kontrol et
                user_policies = self.iam.list_attached_user_policies(UserName=user_name)
                for policy in user_policies['AttachedPolicies']:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        admin_users.append(user_name)
                        break
                
                # Inline policies kontrol et
                if user_name not in admin_users:
                    inline_policies = self.iam.list_user_policies(UserName=user_name)
                    for policy_name in inline_policies['PolicyNames']:
                        policy_version = self.iam.get_user_policy(
                            UserName=user_name,
                            PolicyName=policy_name
                        )
                        policy_doc = policy_version['PolicyDocument']
                        
                        # Policy document içinde admin permission kontrolü
                        if self._has_admin_permission(policy_doc):
                            admin_users.append(user_name)
                            break
            
            if admin_users:
                for user_name in admin_users:
                    self.findings.append(Finding(
                        check_id="IAM-ADMIN-USER",
                        resource_id=user_name,
                        severity=Severity.HIGH,
                        title="IAM Kullanıcısında AdministratorAccess Policy'si Var",
                        description=f"Kullanıcı {user_name} AdministratorAccess policy'sine sahip. "
                                   f"Bu kullanıcı AWS kaynakları üzerinde tam yetkiye sahiptir.",
                        evidence="AdministratorAccess policy attached",
                        remedy=self._remedy_admin_user(user_name),
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                    ))
                    
        except ClientError as e:
            print(f"Admin kullanıcı kontrol hatası: {str(e)}")
    
    def _check_mfa_disabled_users(self):
        """MFA devre dışı olan kullanıcıları kontrol et"""
        try:
            # Tüm kullanıcıları listele
            users = []
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            mfa_disabled_users = []
            for user in users:
                user_name = user['UserName']
                
                # MFA cihazlarını kontrol et
                mfa_devices = self.iam.list_mfa_devices(UserName=user_name)
                
                if not mfa_devices['MFADevices']:
                    mfa_disabled_users.append(user_name)
            
            if mfa_disabled_users:
                for user_name in mfa_disabled_users:
                    self.findings.append(Finding(
                        check_id="IAM-NO-MFA",
                        resource_id=user_name,
                        severity=Severity.HIGH,
                        title="IAM Kullanıcısında MFA Aktif Değil",
                        description=f"Kullanıcı {user_name} için MFA aktif değil. "
                                   f"MFA olmadan hesap çalınması riski çok yüksektir.",
                        evidence="ListMFADevices boş döndü",
                        remedy=self._remedy_mfa_disabled(user_name),
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html"
                    ))
                    
        except ClientError as e:
            print(f"MFA kontrol hatası: {str(e)}")
    
    def _check_old_access_keys(self):
        """90 günden eski access key'leri kontrol et"""
        try:
            # Tüm kullanıcıları listele
            users = []
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            old_keys = []
            for user in users:
                user_name = user['UserName']
                
                # Access key'leri kontrol et
                access_keys = self.iam.list_access_keys(UserName=user_name)
                
                for key in access_keys['AccessKeyMetadata']:
                    key_id = key['AccessKeyId']
                    create_date = key['CreateDate']
                    
                    # Key yaşını hesapla
                    age = datetime.now(create_date.tzinfo) - create_date
                    
                    if age > timedelta(days=90):
                        old_keys.append({
                            'user': user_name,
                            'key_id': key_id,
                            'age_days': age.days
                        })
            
            if old_keys:
                for key_info in old_keys:
                    self.findings.append(Finding(
                        check_id="IAM-OLD-ACCESS-KEY",
                        resource_id=f"{key_info['user']}/{key_info['key_id']}",
                        severity=Severity.MEDIUM,
                        title="90 Günden Eski Access Key Tespit Edildi",
                        description=f"Kullanıcı {key_info['user']} için access key "
                                   f"({key_info['key_id']}) {key_info['age_days']} gün önce oluşturulmuş. "
                                   f"Eski key'ler güvenlik riski oluşturabilir.",
                        evidence=f"Key yaşı: {key_info['age_days']} gün",
                        remedy=self._remedy_old_access_key(key_info['user'], key_info['key_id']),
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
                    ))
                    
        except ClientError as e:
            print(f"Access key kontrol hatası: {str(e)}")
    
    def _check_wildcard_policies(self):
        """Wildcard (*:*) yetkisi içeren policy'leri kontrol et"""
        try:
            # Tüm kullanıcı policy'lerini kontrol et
            users = []
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            wildcard_policies = []
            for user in users:
                user_name = user['UserName']
                
                # Inline policies kontrol et
                inline_policies = self.iam.list_user_policies(UserName=user_name)
                for policy_name in inline_policies['PolicyNames']:
                    try:
                        policy_version = self.iam.get_user_policy(
                            UserName=user_name,
                            PolicyName=policy_name
                        )
                        policy_doc = policy_version['PolicyDocument']
                        
                        if self._has_wildcard_permission(policy_doc):
                            wildcard_policies.append({
                                'user': user_name,
                                'policy': policy_name,
                                'type': 'inline'
                            })
                    except ClientError as e:
                        print(f"Policy okuma hatası: {str(e)}")
                
                # Attached policies kontrol et
                user_policies = self.iam.list_attached_user_policies(UserName=user_name)
                for policy in user_policies['AttachedPolicies']:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['PolicyArn']
                    
                    # Managed policy version'larını al
                    policy_versions = self.iam.list_policy_versions(PolicyArn=policy_arn)
                    for version in policy_versions['Versions']:
                        if version['IsDefaultVersion']:
                            try:
                                policy_doc = self.iam.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=version['VersionId']
                                )
                                policy_version_doc = policy_doc['PolicyVersion']['Document']
                                
                                if self._has_wildcard_permission(policy_version_doc):
                                    wildcard_policies.append({
                                        'user': user_name,
                                        'policy': policy_name,
                                        'type': 'managed'
                                    })
                            except ClientError as e:
                                print(f"Managed policy okuma hatası: {str(e)}")
                            break
            
            if wildcard_policies:
                for policy_info in wildcard_policies:
                    self.findings.append(Finding(
                        check_id="IAM-WILDCARD-POLICY",
                        resource_id=f"{policy_info['user']}/{policy_info['policy']}",
                        severity=Severity.HIGH,
                        title="IAM Policy'sinde Wildcard (*:*) Yetkisi Bulundu",
                        description=f"Kullanıcı {policy_info['user']} için policy "
                                   f"{policy_info['policy']} içinde wildcard (*:*) yetkisi var. "
                                   f"Bu durum tüm AWS servislerine tam erişim verir.",
                        evidence="Policy JSON içinde 'Action': '*' veya 'Resource': '*' bulundu",
                        remedy=self._remedy_wildcard_policy(policy_info['user'], policy_info['policy']),
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                    ))
                    
        except ClientError as e:
            print(f"Wildcard policy kontrol hatası: {str(e)}")
    
    def _has_admin_permission(self, policy_doc):
        """Policy document'inde admin permission olup olmadığını kontrol et"""
        statements = policy_doc.get('Statement', [])
        
        for statement in statements:
            effect = statement.get('Effect', '')
            if effect != 'Allow':
                continue
            
            action = statement.get('Action', [])
            resource = statement.get('Resource', [])
            
            # Action ve resource kontrolü
            actions = action if isinstance(action, list) else [action]
            resources = resource if isinstance(resource, list) else [resource]
            
            # AdministratorAccess control
            if '*:*' in actions or '*' in actions:
                if '*' in resources or '*/*' in resources:
                    return True
            
            # Çok geniş permission kontrolü
            if '*' in actions and '*' in resources:
                return True
        
        return False
    
    def _has_wildcard_permission(self, policy_doc):
        """Policy document'inde wildcard permission olup olmadığını kontrol et"""
        statements = policy_doc.get('Statement', [])
        
        for statement in statements:
            effect = statement.get('Effect', '')
            if effect != 'Allow':
                continue
            
            action = statement.get('Action', [])
            resource = statement.get('Resource', [])
            
            actions = action if isinstance(action, list) else [action]
            resources = resource if isinstance(resource, list) else [resource]
            
            # Her iki tarafında wildcard kontrolü
            if '*' in actions and '*' in resources:
                return True
            
            # Action wildcard ve resource wildcard
            if '*:*' in actions and '*' in resources:
                return True
        
        return False
    
    def _remedy_admin_user(self, user_name):
        """Admin user düzeltme önerisi"""
        return f"""
**AWS Console:**
1. IAM konsoluna gidin
2. Users kısmından {user_name} kullanıcısını seçin
3. Permissions sekmesine tıklayın
4. AdministratorAccess policy'sini kaldırın
5. Kullanıcıya gerekli minimum yetkileri verin (least privilege)

**AWS CLI:**
```bash
# Admin policy'yi kaldır
aws iam detach-user-policy \\
    --user-name {user_name} \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Gerekli özel policy'yi ekleyin (custom-policy.json ile)
aws iam attach-user-policy \\
    --user-name {user_name} \\
    --policy-arn arn:aws:iam::ACCOUNT_ID:policy/CustomPolicyName
```
"""
    
    def _remedy_mfa_disabled(self, user_name):
        """MFA disabled düzeltme önerisi"""
        return f"""
**AWS Console:**
1. IAM konsoluna gidin
2. Security credentials sekmesine tıklayın
3. {user_name} kullanıcısını seçin
4. Assigned MFA device kısmında Activate MFA'ya tıklayın
5. MFA device tipini seçin (Virtual MFA, Hardware MFA vb.)
6. MFA kurulumunu tamamlayın

**AWS CLI:**
```bash
# Virtual MFA device'ı etkinleştir
aws iam enable-mfa-device \\
    --user-name {user_name} \\
    --serial-number arn:aws:iam::ACCOUNT_ID:mfa/{user_name} \\
    --authentication-code-1 CODE1 \\
    --authentication-code-2 CODE2
```
"""
    
    def _remedy_old_access_key(self, user_name, key_id):
        """Eski access key düzeltme önerisi"""
        return f"""
**AWS Console:**
1. IAM konsoluna gidin
2. {user_name} kullanıcısını seçin
3. Security credentials sekmesine tıklayın
4. Access keys kısmında {key_id} anahtarını bulun
5. Make inactive diyerek devre dışı bırakın
6. Create access key ile yeni anahtar oluşturun
7. Eski anahtarı Delete ile tamamen silin

**AWS CLI:**
```bash
# Eski key'i devre dışı bırak
aws iam update-access-key \\
    --user-name {user_name} \\
    --access-key-id {key_id} \\
    --status Inactive

# Yeni key oluştur
aws iam create-access-key --user-name {user_name}

# Eski key'i sil (kullanımdan emin olduktan sonra)
aws iam delete-access-key \\
    --user-name {user_name} \\
    --access-key-id {key_id}
```
"""
    
    def _remedy_wildcard_policy(self, user_name, policy_name):
        """Wildcard policy düzeltme önerisi"""
        return f"""
**AWS Console:**
1. IAM konsoluna gidin
2. {user_name} kullanıcısını seçin
3. Permissions sekmesine tıklayın
4. {policy_name} policy'sini bulun
5. Edit diyerek policy'yi güncelleyin
6. '*' wildcard'ları kaldırın, gerekli spesifik yetkileri tanımlayın

**AWS CLI:**
```bash
# İlk olarak mevcut policy'i görüntüleyin
aws iam get-user-policy \\
    --user-name {user_name} \\
    --policy-name {policy_name}

# Policy'i güncelleyin (updated-policy.json ile wildcard'ları kaldırarak)
aws iam put-user-policy \\
    --user-name {user_name} \\
    --policy-name {policy_name} \\
    --policy-document file://updated-policy.json
```

**Best Practice:**
- IAM Policy Simulator'ı kullanarak minimum gerekli yetkileri belirleyin
- Least privilege ilkesine uyarak sadece gerekli permission'ları verin
- Resource ARN'larını spesifik olarak tanımlayın
"""