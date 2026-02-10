"""
KMS Checks (Read-only)
- Customer managed key rotation enabled?
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
        "service": "kms",
    }

class KMSCheck:
    def __init__(self, kms_client):
        self.kms = kms_client

    def run_all_checks(self):
        findings = []
        paginator = self.kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for k in page.get("Keys", []):
                key_id = k.get("KeyId")
                if not key_id:
                    continue

                desc = self.kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                if desc.get("KeyManager") != "CUSTOMER":
                    continue
                if desc.get("KeyState") != "Enabled":
                    continue

                try:
                    rot = self.kms.get_key_rotation_status(KeyId=key_id)
                    enabled = rot.get("KeyRotationEnabled", False)
                except Exception:
                    continue

                if not enabled:
                    alias = desc.get("Arn", key_id)
                    findings.append(_mk(
                        "KMS-ROTATION-OFF",
                        "KMS Customer Managed Key rotation kapalı",
                        "low",
                        alias,
                        "Key rotation, uzun süre aynı anahtar materyalinin kullanılmasını engelleyerek riski azaltır.",
                        f"{key_id} KeyRotationEnabled = False",
                        ["KMS Console → Customer managed keys", f"Key seç → Key rotation", "Enable automatic key rotation", "Save"],
                        f"aws kms enable-key-rotation --key-id {key_id}",
                        "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
                        3
                    ))
        return findings
