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
            users = []
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page.get("Users", []))

            admin_users = []

            for user in users:
                user_name = user["UserName"]

                # Attached policies kontrol et
                user_policies = self.iam.list_attached_user_policies(UserName=user_name)
                for policy in user_policies.get("AttachedPolicies", []):
                    if policy.get("PolicyName") == "AdministratorAccess":
                        admin_users.append(user_name)
                        break

                # Inline policies kontrol et (admin değilse)
                if user_name not in admin_users:
                    inline_policies = self.iam.list_user_policies(UserName=user_name)
                    for policy_name in inline_policies.get("PolicyNames", []):
                        policy_version = self.iam.get_user_policy(
                            UserName=user_name,
                            PolicyName=policy_name
                        )
                        policy_doc = policy_version.get("PolicyDocument", {})
                        if self._has_admin_permission(policy_doc):
                            admin_users.append(user_name)
                            break

            # Duplicate temizle
            admin_users = sorted(set(admin_users))

            for user_name in admin_users:
                self.findings.append(Finding(
                    check_id="IAM-ADMIN-USER",
                    service="iam",
                    resource=user_name,
                    severity=Severity.HIGH,
                    title="IAM Kullanıcısında AdministratorAccess Policy'si Var",
                    why=(
                        f"Kullanıcı '{user_name}' AdministratorAccess policy'sine sahip. "
                        f"Bu kullanıcı AWS kaynakları üzerinde tam yetkiye sahiptir."
                    ),
                    evidence="AdministratorAccess policy attached veya inline admin yetki tespit edildi",
                    remediation_console=self._remedy_admin_user(user_name),
                    remediation_cli="",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                    points=15
                ))

        except ClientError as e:
            print(f"Admin kullanıcı kontrol hatası: {str(e)}")

    def _check_mfa_disabled_users(self):
        """MFA devre dışı olan kullanıcıları kontrol et"""
        try:
            users = []
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page.get("Users", []))

            mfa_disabled_users = []

            for user in users:
                user_name = user["UserName"]

                mfa_devices = self.iam.list_mfa_devices(UserName=user_name)
                if not mfa_devices.get("MFADevices", []):
                    mfa_disabled_users.append(user_name)

            # ✅ Döngü bittikten sonra duplicate temizle
            mfa_disabled_users = sorted(set(mfa_disabled_users))

            for user_name in mfa_disabled_users:
                self.findings.append(Finding(
                    check_id="IAM-NO-MFA",
                    service="iam",
                    resource=user_name,
                    severity=Severity.HIGH,
                    title="IAM Kullanıcısında MFA Aktif Değil",
                    why=(
                        f"IAM kullanıcısı '{user_name}' için MFA aktif değil. "
                        f"MFA olmadan hesap ele geçirilmesi riski çok yüksektir."
                    ),
                    evidence="ListMFADevices sonucu: 0 cihaz",
                    remediation_console=(
                        "AWS Console > IAM > Users > kullanıcıyı seç > "
                        "Security credentials > Assign MFA device"
                    ),
                    remediation_cli=(
                        "aws iam list-mfa-devices --user-name <USER>\n"
                        "# MFA ekleme işlemi fiziksel/sanal cihaz ile yapılır"
                    ),
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html",
                    points=15
                ))

        except ClientError as e:
            print(f"MFA kontrol hatası: {str(e)}")

    def _check_old_access_keys(self):
        """90 günden eski access key'leri kontrol et"""
        try:
            users = []
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page.get("Users", []))

            old_keys = []
            for user in users:
                user_name = user["UserName"]

                access_keys = self.iam.list_access_keys(UserName=user_name)
                for key in access_keys.get("AccessKeyMetadata", []):
                    key_id = key["AccessKeyId"]
                    create_date = key["CreateDate"]

                    age = datetime.now(create_date.tzinfo) - create_date
                    if age > timedelta(days=90):
                        old_keys.append((user_name, key_id, age.days))

            for user_name, key_id, age_days in old_keys:
                self.findings.append(Finding(
                    check_id="IAM-OLD-ACCESS-KEY",
                    service="iam",
                    resource=f"{user_name}/{key_id}",
                    severity=Severity.MEDIUM,
                    title="90 Günden Eski Access Key Tespit Edildi",
                    why=(
                        f"Kullanıcı '{user_name}' için access key ({key_id}) {age_days} gün önce oluşturulmuş. "
                        f"Eski key'ler güvenlik riski oluşturabilir."
                    ),
                    evidence=f"Key yaşı: {age_days} gün",
                    remediation_console=self._remedy_old_access_key(user_name, key_id),
                    remediation_cli="",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
                    points=8
                ))

        except ClientError as e:
            print(f"Access key kontrol hatası: {str(e)}")

    def _check_wildcard_policies(self):
        """Wildcard (*:*) yetkisi içeren policy'leri kontrol et"""
        try:
            users = []
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page.get("Users", []))

            wildcard_hits = []

            for user in users:
                user_name = user["UserName"]

                # Inline policies
                inline_policies = self.iam.list_user_policies(UserName=user_name)
                for policy_name in inline_policies.get("PolicyNames", []):
                    try:
                        policy_version = self.iam.get_user_policy(
                            UserName=user_name,
                            PolicyName=policy_name
                        )
                        policy_doc = policy_version.get("PolicyDocument", {})
                        if self._has_wildcard_permission(policy_doc):
                            wildcard_hits.append((user_name, policy_name, "inline"))
                    except ClientError as e:
                        print(f"Policy okuma hatası: {str(e)}")

                # Attached policies (managed)
                user_policies = self.iam.list_attached_user_policies(UserName=user_name)
                for policy in user_policies.get("AttachedPolicies", []):
                    policy_name = policy["PolicyName"]
                    policy_arn = policy["PolicyArn"]

                    policy_versions = self.iam.list_policy_versions(PolicyArn=policy_arn)
                    for version in policy_versions.get("Versions", []):
                        if version.get("IsDefaultVersion"):
                            try:
                                policy_doc = self.iam.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=version["VersionId"]
                                )
                                policy_version_doc = policy_doc.get("PolicyVersion", {}).get("Document", {})
                                if self._has_wildcard_permission(policy_version_doc):
                                    wildcard_hits.append((user_name, policy_name, "managed"))
                            except ClientError as e:
                                print(f"Managed policy okuma hatası: {str(e)}")
                            break

            # Duplicate temizle
            wildcard_hits = sorted(set(wildcard_hits))

            for user_name, policy_name, ptype in wildcard_hits:
                self.findings.append(Finding(
                    check_id="IAM-WILDCARD-POLICY",
                    service="iam",
                    resource=f"{user_name}/{policy_name}",
                    severity=Severity.HIGH,
                    title="IAM Policy'sinde Wildcard Yetkisi Bulundu",
                    why=(
                        f"Kullanıcı '{user_name}' için policy '{policy_name}' ({ptype}) içinde wildcard yetkiler tespit edildi. "
                        f"Bu durum gereksiz geniş erişim riski oluşturur."
                    ),
                    evidence="Policy JSON içinde 'Action': '*' veya 'Resource': '*' bulundu",
                    remediation_console=self._remedy_wildcard_policy(user_name, policy_name),
                    remediation_cli="",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                    points=15
                ))

        except ClientError as e:
            print(f"Wildcard policy kontrol hatası: {str(e)}")

    def _has_admin_permission(self, policy_doc):
        """Policy document'inde admin permission olup olmadığını kontrol et"""
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            action = statement.get("Action", [])
            resource = statement.get("Resource", [])

            actions = action if isinstance(action, list) else [action]
            resources = resource if isinstance(resource, list) else [resource]

            if ("*" in actions or "*:*" in actions) and "*" in resources:
                return True

        return False

    def _has_wildcard_permission(self, policy_doc):
        """Policy document'inde wildcard permission olup olmadığını kontrol et"""
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            action = statement.get("Action", [])
            resource = statement.get("Resource", [])

            actions = action if isinstance(action, list) else [action]
            resources = resource if isinstance(resource, list) else [resource]

            if ("*" in actions or "*:*" in actions) and "*" in resources:
                return True

        return False

    def _remedy_admin_user(self, user_name):
        """Admin user düzeltme önerisi"""
        return f"""
AWS Console:
1. IAM konsoluna gidin
2. Users kısmından {user_name} kullanıcısını seçin
3. Permissions sekmesine tıklayın
4. AdministratorAccess policy'sini kaldırın
5. Kullanıcıya gerekli minimum yetkileri verin (least privilege)
"""

    def _remedy_mfa_disabled(self, user_name):
        """MFA disabled düzeltme önerisi"""
        return f"""
AWS Console:
1. IAM konsoluna gidin
2. Users kısmından {user_name} kullanıcısını seçin
3. Security credentials sekmesine tıklayın
4. Assigned MFA device kısmında Assign MFA device'a tıklayın
"""

    def _remedy_old_access_key(self, user_name, key_id):
        """Eski access key düzeltme önerisi"""
        return f"""
AWS Console:
1. IAM konsoluna gidin
2. {user_name} kullanıcısını seçin
3. Security credentials sekmesi > Access keys
4. {key_id} anahtarını Inactive yapın, yeni key üretin, sonra silin
"""

    def _remedy_wildcard_policy(self, user_name, policy_name):
        """Wildcard policy düzeltme önerisi"""
        return f"""
AWS Console:
1. IAM konsoluna gidin
2. {user_name} kullanıcısını seçin
3. Permissions sekmesine tıklayın
4. {policy_name} policy'sini bulun
5. '*' wildcard'ları kaldırın, gerekli spesifik yetkileri tanımlayın
"""
