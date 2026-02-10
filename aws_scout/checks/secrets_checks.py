"""
Secrets Manager Checks (Read-only)
- Rotation enabled?
"""
from __future__ import annotations

def _mk(fid, title, severity, resource, why, evidence, console, cli, ref, points):
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "resource": resource,
        "why": why,
        "evidence": evidence,
        "remediation_console": console,
        "remediation_cli": cli,
        "reference": ref,
        "points": points,
        "service": "secretsmanager",
    }

class SecretsCheck:
    def __init__(self, secrets_client):
        self.sm = secrets_client

    def run_all_checks(self):
        findings = []
        paginator = self.sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for s in page.get("SecretList", []):
                arn = s.get("ARN", "unknown-secret")
                name = s.get("Name", arn)

                # list_secrets bazen RotationEnabled vermez; describe_secret ile netleşir
                try:
                    desc = self.sm.describe_secret(SecretId=arn)
                except Exception:
                    continue

                rotation = desc.get("RotationEnabled", False)
                if not rotation:
                    findings.append(_mk(
                        "SM-ROTATION-OFF",
                        "Secrets Manager secret rotation kapalı",
                        "medium",
                        name,
                        "Rotation kapalıysa uzun yaşayan secret'lar risk yaratır. Otomatik rotation önerilir.",
                        f"{name} RotationEnabled = False",
                        ["Secrets Manager Console → Secrets", f"{name} seç", "Rotation → Enable rotation", "Rotation schedule ayarla", "Save"],
                        f"# Rotation için Lambda gerekir (AWS wizard ile oluşturulabilir)\naws secretsmanager describe-secret --secret-id \"{arn}\"",
                        "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
                        8
                    ))
        return findings
