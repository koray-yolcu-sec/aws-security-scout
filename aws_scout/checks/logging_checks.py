"""
CloudWatch Logs Checks (Read-only)
- Log group retention policy set?
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
        "service": "logs",
    }

class LoggingCheck:
    def __init__(self, logs_client):
        self.logs = logs_client

    def run_all_checks(self):
        findings = []
        paginator = self.logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                name = lg.get("logGroupName", "unknown-log-group")
                retention = lg.get("retentionInDays")  # None ise never expire
                if retention is None:
                    findings.append(_mk(
                        "LOGS-NO-RETENTION",
                        "CloudWatch Log Group retention policy ayarlı değil",
                        "low",
                        name,
                        "Retention yoksa loglar sınırsız büyür (maliyet) ve governance/compliance yönetimi zorlaşır.",
                        f"{name} retentionInDays = None",
                        ["CloudWatch Console → Log groups", f"{name} seç", "Actions → Edit retention setting", "Uygun gün sayısını seç (örn 30/90/180)", "Save"],
                        f"aws logs put-retention-policy --log-group-name \"{name}\" --retention-in-days 90",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html",
                        3
                    ))
        return findings
