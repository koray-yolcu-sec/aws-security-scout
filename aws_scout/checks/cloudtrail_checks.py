"""
CloudTrail Checks (Read-only)
- CloudTrail enabled?
- Multi-region trail?
- Log file validation enabled?
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
        "service": "cloudtrail",
    }

class CloudTrailCheck:
    def __init__(self, cloudtrail_client):
        self.ct = cloudtrail_client

    def run_all_checks(self):
        findings = []
        findings += self.check_cloudtrail_exists()
        findings += self.check_cloudtrail_settings()
        return findings

    def check_cloudtrail_exists(self):
        resp = self.ct.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", []) or []
        if not trails:
            return [_mk(
                "CT-NO-TRAIL",
                "CloudTrail aktif değil (trail bulunamadı)",
                "high",
                "cloudtrail",
                "CloudTrail olmadan audit/forensic görünürlüğü düşer.",
                "describe_trails sonucu boş",
                ["CloudTrail Console → Trails → Create trail", "Multi-region önerilir", "Management events enabled"],
                "aws cloudtrail describe-trails",
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html",
                15
            )]
        return []

    def check_cloudtrail_settings(self):
        findings = []
        resp = self.ct.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", []) or []
        for t in trails:
            name = t.get("Name", "unknown-trail")
            is_multi = t.get("IsMultiRegionTrail", False)
            log_validation = t.get("LogFileValidationEnabled", False)

            if not is_multi:
                findings.append(_mk(
                    "CT-NOT-MULTIREGION",
                    "CloudTrail multi-region değil",
                    "medium",
                    name,
                    "Sadece tek region trail'i kör noktalara sebep olabilir. Multi-region trail önerilir.",
                    f"{name} IsMultiRegionTrail = False",
                    ["CloudTrail Console → Trails", f"{name} seç → Edit", "Multi-region trail: Enable", "Save"],
                    f"aws cloudtrail update-trail --name {name} --is-multi-region-trail",
                    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html",
                    8
                ))

            if not log_validation:
                findings.append(_mk(
                    "CT-LOG-VALIDATION-OFF",
                    "CloudTrail Log File Validation kapalı",
                    "low",
                    name,
                    "Log file validation, log bütünlüğünü doğrulamada yardımcı olur.",
                    f"{name} LogFileValidationEnabled = False",
                    ["CloudTrail Console → Trails", f"{name} seç → Edit", "Log file validation: Enable", "Save"],
                    f"aws cloudtrail update-trail --name {name} --enable-log-file-validation",
                    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
                    3
                ))
        return findings
