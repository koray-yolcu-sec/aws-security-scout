"""
EC2 & Network Checks (Read-only)
- Security Group 0.0.0.0/0 risky ports (SSH/RDP/MySQL/Postgres)
- Instance Metadata: IMDSv1 enabled?
- EBS encryption enabled?
"""
from __future__ import annotations

RISKY_PORTS = {
    22:  ("SSH (22)", "EC2-SG-SSH-OPEN", "high"),
    3389:("RDP (3389)", "EC2-SG-RDP-OPEN", "high"),
    3306:("MySQL (3306)", "EC2-SG-MYSQL-OPEN", "high"),
    5432:("Postgres (5432)", "EC2-SG-PG-OPEN", "medium"),
}

def _mk_finding(fid: str, title: str, severity: str, resource: str, why: str, evidence: str,
                console_steps: list[str], cli_cmd: str, reference: str, points: int):
    return {
        "id": fid,
        "title": title,
        "severity": severity,      # 'critical' | 'high' | 'medium' | 'low'
        "resource": resource,
        "why": why,
        "evidence": evidence,
        "remediation_console": console_steps,
        "remediation_cli": cli_cmd,
        "reference": reference,
        "points": points,
        "service": "ec2",
    }

class EC2Check:
    def __init__(self, ec2_client):
        self.ec2 = ec2_client

    def run_all_checks(self):
        findings = []
        findings += self.check_security_groups_world_open()
        findings += self.check_imdsv1_enabled()
        findings += self.check_ebs_encryption()
        return findings

    def check_security_groups_world_open(self):
        findings = []
        resp = self.ec2.describe_security_groups()
        sgs = resp.get("SecurityGroups", [])
        for sg in sgs:
            sg_id = sg.get("GroupId", "unknown-sg")
            sg_name = sg.get("GroupName", "")
            for perm in sg.get("IpPermissions", []):
                from_p = perm.get("FromPort")
                to_p = perm.get("ToPort")
                ip_ranges = perm.get("IpRanges", [])
                if from_p is None or to_p is None:
                    continue
                for r in ip_ranges:
                    cidr = r.get("CidrIp")
                    if cidr != "0.0.0.0/0":
                        continue
                    # port aralığı risky port içeriyor mu?
                    for p, (pname, fid, sev) in RISKY_PORTS.items():
                        if from_p <= p <= to_p:
                            title = f"Security Group dünyaya açık: {pname}"
                            why = "0.0.0.0/0 ile kritik portların açık olması brute-force ve yetkisiz erişim riskini artırır."
                            evidence = f"{sg_id} ({sg_name}) inbound {from_p}-{to_p} → {cidr}"
                            console = [
                                "EC2 Console → Security Groups",
                                f"{sg_id} security group'unu açın",
                                "Inbound rules → Edit inbound rules",
                                "0.0.0.0/0 kuralını kaldırın veya sadece kendi IP'nizle sınırlandırın",
                                "Save rules",
                            ]
                            cli = f"# SG inbound kuralını gözden geçirin\naws ec2 describe-security-groups --group-ids {sg_id}"
                            ref = "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"
                            points = 15 if sev == "high" else 8
                            findings.append(_mk_finding(fid, title, sev, sg_id, why, evidence, console, cli, ref, points))
        return findings

    def check_imdsv1_enabled(self):
        findings = []
        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for r in page.get("Reservations", []):
                for inst in r.get("Instances", []):
                    iid = inst.get("InstanceId", "unknown-instance")
                    meta = inst.get("MetadataOptions", {}) or {}
                    http_tokens = meta.get("HttpTokens")  # 'required' = IMDSv2 zorunlu, 'optional' = IMDSv1 mümkün
                    if http_tokens == "optional":
                        title = "EC2 Instance IMDSv1 kapatılmamış (IMDSv2 zorunlu değil)"
                        why = "IMDSv1 SSRF gibi saldırılara daha açıktır. IMDSv2 zorunlu yapmak önerilir."
                        evidence = f"{iid} MetadataOptions.HttpTokens = optional"
                        console = [
                            "EC2 Console → Instances",
                            f"{iid} instance'ını seçin",
                            "Actions → Security → Modify instance metadata options",
                            "IMDSv2: 'Require token' (HttpTokens=required) seçin",
                            "Save",
                        ]
                        cli = f"aws ec2 modify-instance-metadata-options --instance-id {iid} --http-tokens required"
                        ref = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"
                        findings.append(_mk_finding("EC2-IMDSV1-ENABLED", title, "high", iid, why, evidence, console, cli, ref, 15))
        return findings

    def check_ebs_encryption(self):
        findings = []
        paginator = self.ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                vid = vol.get("VolumeId", "unknown-vol")
                encrypted = vol.get("Encrypted", True)
                if not encrypted:
                    title = "EBS Volume şifreleme kapalı"
                    why = "Disk şifreleme kapalıysa veri sızıntısı ve compliance riskleri artar."
                    evidence = f"{vid} Encrypted = False"
                    console = [
                        "EC2 Console → Volumes",
                        f"{vid} volume'ünü bulun",
                        "Not: EBS encryption sonradan direkt açılmaz; snapshot alıp encrypted volume ile restore gerekir.",
                        "Snapshot oluştur → Copy snapshot (encrypt) → new volume oluştur → instance'a attach",
                    ]
                    cli = (
                        "# Not: Doğrudan enable edemezsin, snapshot workflow gerekir.\n"
                        f"aws ec2 describe-volumes --volume-ids {vid}"
                    )
                    ref = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
                    findings.append(_mk_finding("EC2-EBS-UNENCRYPTED", title, "medium", vid, why, evidence, console, cli, ref, 8))
        return findings
