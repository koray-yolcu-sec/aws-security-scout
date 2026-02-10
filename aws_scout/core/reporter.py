"""
Reporter Module
Güvenlik raporlarının oluşturulması ve formatlanması
"""
import json
from datetime import datetime
from jinja2 import Template, Environment, FileSystemLoader
from ..core.scorer import Severity


class Reporter:
    """Raporlama sınıfı"""
    
    def __init__(self, locale='tr', locale_dir='aws_scout/locales'):
        """
        Reporter başlatıcı
        
        Args:
            locale: Dil kodu ('tr' veya 'en')
            locale_dir: Locale dosyalarının dizini
        """
        self.locale = locale
        self.locale_data = self._load_locale(locale_dir)
    
    def _load_locale(self, locale_dir):
        """Locale dosyasını yükle"""
        locale_file = f"{locale_dir}/{self.locale}.json"
        try:
            with open(locale_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Locale dosyası bulunamadı: {locale_file}, varsayılan 'tr' kullanılıyor")
            with open(f"{locale_dir}/tr.json", 'r', encoding='utf-8') as f:
                return json.load(f)
    
    def _get_text(self, key):
        """Locale'den metin al"""
        keys = key.split('.')
        value = self.locale_data
        for k in keys:
            value = value.get(k, key)
        return value
    
    def generate_markdown_report(self, account_id, findings, score, output_file='report.md'):
        """
        Markdown formatında rapor oluştur
        
        Args:
            account_id: AWS hesap ID'si
            findings: Finding listesi
            score: Güvenlik skoru
            output_file: Çıktı dosya adı
            
        Returns:
            str: Rapor içeriği
        """
        # Risk seviyesini belirle
        risk_level, risk_color = self._get_risk_level(score)
        
        # Bulguları özetle
        summary = self._summarize_findings(findings)
        
        # Hızlı düzeltmeler ve yüksek etki düzeltmeleri
        quick_wins = self._get_quick_wins(findings)
        high_impact = self._get_high_impact(findings)
        
        # Rapor içeriğini oluştur
        content = f"""# {self._get_text('report.title')}

---

## {self._get_text('report.generated_on')}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
## {self._get_text('report.account_id')}: `{account_id}`
## {self._get_text('report.security_score')}: **{score}/100**
## {self._get_text('report.risk_status')}: <span style="color:{risk_color}">**{risk_level}**</span>

---

## {self._get_text('report.summary')}

| {self._get_text('severity.critical')} | {self._get_text('severity.high')} | {self._get_text('severity.medium')} | {self._get_text('severity.low')} | {self._get_text('report.total_findings')} |
|:---:|:---:|:---:|:---:|:---:|
| {summary['critical']} | {summary['high']} | {summary['medium']} | {summary['low']} | {summary['total']} |

"""
        
        # Hızlı düzeltmeler bölümü
        if quick_wins:
            content += f"## {self._get_text('report.quick_wins')}\\n\\n"
            for i, finding in enumerate(quick_wins, 1):
                severity_name = Severity.get_name(finding.severity)
                content += f"**{i}. {finding.title}**\\n"
                content += f"- **Kaynak**: `{finding.resource_id}`\\n"
                content += f"- **Severity**: {self._get_text(f'severity.{severity_name.lower()}')}\\n"
                content += f"- **Puan**: +{finding.points}\\n\\n"
            
            content += "---\\n\\n"
        
        # Yüksek etki düzeltmeleri bölümü
        if high_impact:
            content += f"## {self._get_text('report.high_impact')}\\n\\n"
            for i, finding in enumerate(high_impact, 1):
                severity_name = Severity.get_name(finding.severity)
                content += f"**{i}. {finding.title}**\\n"
                content += f"- **Kaynak**: `{finding.resource_id}`\\n"
                content += f"- **Severity**: {self._get_text(f'severity.{severity_name.lower()}')}\\n"
                content += f"- **Puan**: +{finding.points}\\n\\n"
            
            content += "---\\n\\n"
        
        # Detaylı bulgular bölümü
        content += f"## {self._get_text('report.detailed_findings')}\\n\\n"
        
        if not findings:
            content += f"*{self._get_text('messages.no_findings')}*\\n"
        else:
            for finding in findings:
                severity_name = Severity.get_name(finding.severity)
                severity_color = Severity.get_color(finding.severity)
                
                content += f"### {finding.title}\\n\\n"
                content += f"- **{self._get_text('report.finding_title')} ID**: `{finding.check_id}`\\n"
                content += f"- **{self._get_text('severity')}**: <span style='color:{severity_color}'>**{self._get_text(f'severity.{severity_name.lower()}')}**</span>\\n"
                content += f"- **{self._get_text('resource')}**: `{finding.resource_id}`\\n"
                content += f"- **{self._get_text('report.why_important')}**: {finding.description}\\n"
                content += f"- **{self._get_text('report.evidence')}**: `{finding.evidence}`\\n\\n"
                content += f"#### {self._get_text('report.remedy')}\\n\\n"
                content += f"{finding.remedy}\\n\\n"
                
                if finding.reference:
                    content += f"**{self._get_text('report.reference')}**: {finding.reference}\\n"
                
                content += "---\\n\\n"
        
        # Footer
        content += f"\\n---\\n\\n"
        content += f"*{self._get_text('report.generated_on')}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\\n"
        content += f"*{self._get_text('footer.generated_by')} {self._get_text('app_name')}*\\n"
        content += f"*{self._get_text('footer.no_modifications')}*\\n"
        content += f"*{self._get_text('footer.disclaimer')}*\\n"
        
        # Dosyaya kaydet
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return content
    
    def generate_html_report(self, account_id, findings, score, output_file='report.html'):
        """
        HTML formatında rapor oluştur
        
        Args:
            account_id: AWS hesap ID'si
            findings: Finding listesi
            score: Güvenlik skoru
            output_file: Çıktı dosya adı
            
        Returns:
            str: Rapor içeriği
        """
        # Risk seviyesini belirle
        risk_level, risk_color = self._get_risk_level(score)
        
        # Bulguları özetle
        summary = self._summarize_findings(findings)
        
        # Hızlı düzeltmeler ve yüksek etki düzeltmeleri
        quick_wins = self._get_quick_wins(findings)
        high_impact = self._get_high_impact(findings)
        
        # Severity sıralaması
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99)
        
        # HTML template
        html_template = """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report_title }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #2c3e50;
            margin-bottom: 20px;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        
        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
        }
        
        h3 {
            color: #2c3e50;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        
        .header-info {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .header-info p {
            margin: 5px 0;
        }
        
        .score-box {
            display: inline-block;
            padding: 15px 25px;
            border-radius: 5px;
            color: white;
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .summary-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .summary-table th,
        .summary-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: center;
        }
        
        .summary-table th {
            background: #34495e;
            color: white;
        }
        
        .finding-card {
            background: #f9f9f9;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }
        
        .finding-card.critical {
            border-left-color: #e74c3c;
        }
        
        .finding-card.high {
            border-left-color: #f39c12;
        }
        
        .finding-card.medium {
            border-left-color: #f1c40f;
        }
        
        .finding-card.low {
            border-left-color: #27ae60;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-size: 12px;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .severity-critical {
            background: #e74c3c;
        }
        
        .severity-high {
            background: #f39c12;
        }
        
        .severity-medium {
            background: #f1c40f;
        }
        
        .severity-low {
            background: #27ae60;
        }
        
        .remedy-box {
            background: #e8f6f3;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        
        .remedy-box h4 {
            color: #16a085;
            margin-bottom: 10px;
        }
        
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        pre {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        pre code {
            background: none;
            color: inherit;
            padding: 0;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 12px;
        }
        
        .quick-wins-section,
        .high-impact-section {
            background: #fff8e1;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        
        .list-item {
            padding: 10px;
            margin: 5px 0;
            background: white;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ report_title }}</h1>
        
        <div class="header-info">
            <p><strong>{{ text_generated_on }}:</strong> {{ generated_on }}</p>
            <p><strong>{{ text_account_id }}:</strong> <code>{{ account_id }}</code></p>
            <p><strong>{{ text_security_score }}:</strong> 
                <span class="score-box" style="background: {{ risk_color }}">{{ score }}/100</span>
            </p>
            <p><strong>{{ text_risk_status }}:</strong> <strong>{{ risk_level }}</strong></p>
        </div>
        
        <h2>{{ text_summary }}</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>{{ text_critical }}</th>
                    <th>{{ text_high }}</th>
                    <th>{{ text_medium }}</th>
                    <th>{{ text_low }}</th>
                    <th>{{ text_total_findings }}</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td style="color: #e74c3c; font-weight: bold">{{ summary.critical }}</td>
                    <td style="color: #f39c12; font-weight: bold">{{ summary.high }}</td>
                    <td style="color: #f1c40f; font-weight: bold">{{ summary.medium }}</td>
                    <td style="color: #27ae60; font-weight: bold">{{ summary.low }}</td>
                    <td style="font-weight: bold">{{ summary.total }}</td>
                </tr>
            </tbody>
        </table>
        
        {% if quick_wins %}
        <div class="quick-wins-section">
            <h2>{{ text_quick_wins }}</h2>
            {% for finding in quick_wins %}
            <div class="list-item">
                <strong>{{ loop.index }}. {{ finding.title }}</strong><br>
                <small>
                    <strong>{{ text_resource }}:</strong> <code>{{ finding.resource_id }}</code> | 
                    <strong>{{ text_severity }}:</strong> {{ finding.severity_name }} | 
                    <strong>{{ text_points }}:</strong> +{{ finding.points }}
                </small>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if high_impact %}
        <div class="high-impact-section">
            <h2>{{ text_high_impact }}</h2>
            {% for finding in high_impact %}
            <div class="list-item">
                <strong>{{ loop.index }}. {{ finding.title }}</strong><br>
                <small>
                    <strong>{{ text_resource }}:</strong> <code>{{ finding.resource_id }}</code> | 
                    <strong>{{ text_severity }}:</strong> {{ finding.severity_name }} | 
                    <strong>{{ text_points }}:</strong> +{{ finding.points }}
                </small>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        <h2>{{ text_detailed_findings }}</h2>
        
        {% if not findings %}
        <p><em>{{ text_no_findings }}</em></p>
        {% else %}
        {% for finding in findings %}
        <div class="finding-card {{ finding.severity_class }}">
            <h3>
                <span class="severity-badge {{ finding.severity_class }}">{{ finding.severity_name }}</span>
                {{ finding.title }}
            </h3>
            
            <p><strong>{{ text_finding_id }}:</strong> <code>{{ finding.check_id }}</code></p>
            <p><strong>{{ text_resource }}:</strong> <code>{{ finding.resource_id }}</code></p>
            <p><strong>{{ text_why_important }}:</strong> {{ finding.description }}</p>
            <p><strong>{{ text_evidence }}:</strong> <code>{{ finding.evidence }}</code></p>
            
            <div class="remedy-box">
                <h4>{{ text_remedy }}</h4>
                <pre><code>{{ finding.remedy }}</code></pre>
            </div>
            
            {% if finding.reference %}
            <p><strong>{{ text_reference }}:</strong> <a href="{{ finding.reference }}" target="_blank">{{ finding.reference }}</a></p>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}
        
        <div class="footer">
            <p>{{ text_generated_on }}: {{ generated_on }}</p>
            <p>{{ text_generated_by }} {{ app_name }}</p>
            <p>{{ text_no_modifications }}</p>
            <p>{{ text_disclaimer }}</p>
        </div>
    </div>
</body>
</html>"""
        
        # Template context'i hazırla
        template = Template(html_template)
        context = {
            'report_title': self._get_text('report.title'),
            'generated_on': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'account_id': account_id,
            'score': score,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'summary': summary,
            'quick_wins': quick_wins,
            'high_impact': high_impact,
            'findings': sorted_findings,
            'text_generated_on': self._get_text('report.generated_on'),
            'text_account_id': self._get_text('report.account_id'),
            'text_security_score': self._get_text('report.security_score'),
            'text_risk_status': self._get_text('report.risk_status'),
            'text_summary': self._get_text('report.summary'),
            'text_critical': self._get_text('severity.critical'),
            'text_high': self._get_text('severity.high'),
            'text_medium': self._get_text('severity.medium'),
            'text_low': self._get_text('severity.low'),
            'text_total_findings': self._get_text('report.total_findings'),
            'text_quick_wins': self._get_text('report.quick_wins'),
            'text_high_impact': self._get_text('report.high_impact'),
            'text_detailed_findings': self._get_text('report.detailed_findings'),
            'text_no_findings': self._get_text('messages.no_findings'),
            'text_finding_id': self._get_text('report.finding_title') + ' ID',
            'text_resource': self._get_text('report.resource'),
            'text_why_important': self._get_text('report.why_important'),
            'text_evidence': self._get_text('report.evidence'),
            'text_remedy': self._get_text('report.remedy'),
            'text_reference': self._get_text('report.reference'),
            'text_severity': self._get_text('report.severity'),
            'text_points': 'Puan',
            'text_generated_by': self._get_text('footer.generated_by'),
            'text_no_modifications': self._get_text('footer.no_modifications'),
            'text_disclaimer': self._get_text('footer.disclaimer'),
            'app_name': self._get_text('app_name')
        }
        
        # Finding'leri context'e ekle (severity class'ları ile)
        findings_with_classes = []
        for finding in sorted_findings:
            severity_name = Severity.get_name(finding.severity).lower()
            findings_with_classes.append({
                'check_id': finding.check_id,
                'resource_id': finding.resource_id,
                'title': finding.title,
                'description': finding.description,
                'evidence': finding.evidence,
                'remedy': finding.remedy,
                'reference': finding.reference,
                'severity_name': self._get_text(f'severity.{severity_name}'),
                'severity_class': f'severity-{severity_name}',
                'points': finding.points
            })
        context['findings'] = findings_with_classes
        
        # Quick wins ve high impact için de aynı işlem
        quick_wins_with_classes = []
        for finding in quick_wins:
            severity_name = Severity.get_name(finding.severity).lower()
            quick_wins_with_classes.append({
                'title': finding.title,
                'resource_id': finding.resource_id,
                'severity_name': self._get_text(f'severity.{severity_name}'),
                'points': finding.points
            })
        context['quick_wins'] = quick_wins_with_classes
        
        high_impact_with_classes = []
        for finding in high_impact:
            severity_name = Severity.get_name(finding.severity).lower()
            high_impact_with_classes.append({
                'title': finding.title,
                'resource_id': finding.resource_id,
                'severity_name': self._get_text(f'severity.{severity_name}'),
                'points': finding.points
            })
        context['high_impact'] = high_impact_with_classes
        
        # HTML oluştur
        html_content = template.render(**context)
        
        # Dosyaya kaydet
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return html_content
    
    def _get_risk_level(self, score):
        """
        Skora göre risk seviyesini belirle
        
        Args:
            score: Güvenlik skoru
            
        Returns:
            tuple: (seviye_adı, renk_kodu)
        """
        if score >= 80:
            return (self._get_text('risk_level.secure'), '#4CAF50')
        elif score >= 50:
            return (self._get_text('risk_level.medium_risk'), '#FFC107')
        else:
            return (self._get_text('risk_level.high_risk'), '#D32F2F')
    
    def _summarize_findings(self, findings):
        """
        Bulguları özetle
        
        Args:
            findings: Finding listesi
            
        Returns:
            dict: Özet istatistikler
        """
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': len(findings)
        }
        
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                summary['critical'] += 1
            elif finding.severity == Severity.HIGH:
                summary['high'] += 1
            elif finding.severity == Severity.MEDIUM:
                summary['medium'] += 1
            elif finding.severity == Severity.LOW:
                summary['low'] += 1
        
        return summary
    
    def _get_quick_wins(self, findings, limit=5):
        """En hızlı düzeltilebilecek bulguları al"""
        sorted_findings = sorted(findings, key=lambda f: f.severity)
        return sorted_findings[:limit]
    
    def _get_high_impact(self, findings, limit=5):
        """En çok puan kazandıran bulguları al"""
        sorted_findings = sorted(findings, key=lambda f: f.severity, reverse=True)
        return sorted_findings[:limit]