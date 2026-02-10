"""Tests for scoring engine and finding normalization"""
import pytest
from aws_scout.core.scorer import Finding, Severity, ScoringEngine


class TestFinding:
    """Test Finding class"""
    
    def test_finding_creation_with_all_params(self):
        """Test finding creation with all parameters"""
        finding = Finding(
            check_id="TEST-001",
            resource_id="test-resource",
            severity=Severity.HIGH,
            title="Test Finding",
            description="Test description",
            evidence="Test evidence",
            remedy="Test remedy",
            reference="https://example.com",
            service="TestService"
        )
        
        assert finding.check_id == "TEST-001"
        assert finding.resource_id == "test-resource"
        assert finding.severity == Severity.HIGH
        assert finding.title == "Test Finding"
        assert finding.description == "Test description"
        assert finding.evidence == "Test evidence"
        assert finding.remedy == "Test remedy"
        assert finding.reference == "https://example.com"
        assert finding.service == "TestService"
        assert finding.points == Severity.HIGH  # Should equal severity
    
    def test_finding_creation_without_service(self):
        """Test finding creation without service parameter (should default to 'General')"""
        finding = Finding(
            check_id="TEST-002",
            resource_id="test-resource-2",
            severity=Severity.MEDIUM,
            title="Test Finding 2",
            description="Test description 2",
            evidence="Test evidence 2",
            remedy="Test remedy 2"
        )
        
        assert finding.service == "General"
        assert finding.points == Severity.MEDIUM
    
    def test_finding_points_match_severity(self):
        """Test that finding points match severity values"""
        critical_finding = Finding("C1", "r1", Severity.CRITICAL, "C", "d", "e", "r")
        high_finding = Finding("H1", "r2", Severity.HIGH, "H", "d", "e", "r")
        medium_finding = Finding("M1", "r3", Severity.MEDIUM, "M", "d", "e", "r")
        low_finding = Finding("L1", "r4", Severity.LOW, "L", "d", "e", "r")
        
        assert critical_finding.points == Severity.CRITICAL
        assert high_finding.points == Severity.HIGH
        assert medium_finding.points == Severity.MEDIUM
        assert low_finding.points == Severity.LOW


class TestSeverity:
    """Test Severity class"""
    
    def test_severity_values(self):
        """Test severity constant values"""
        assert Severity.CRITICAL == 25
        assert Severity.HIGH == 15
        assert Severity.MEDIUM == 8
        assert Severity.LOW == 3
    
    def test_severity_get_name(self):
        """Test severity name mapping"""
        assert Severity.get_name(Severity.CRITICAL) == "Critical"
        assert Severity.get_name(Severity.HIGH) == "High"
        assert Severity.get_name(Severity.MEDIUM) == "Medium"
        assert Severity.get_name(Severity.LOW) == "Low"
        assert Severity.get_name(999) == "Unknown"
    
    def test_severity_get_color(self):
        """Test severity color mapping"""
        assert Severity.get_color(Severity.CRITICAL) == "#D32F2F"
        assert Severity.get_color(Severity.HIGH) == "#F57C00"
        assert Severity.get_color(Severity.MEDIUM) == "#FBC02D"
        assert Severity.get_color(Severity.LOW) == "#388E3C"
        assert Severity.get_color(999) == "#757575"


class TestScoringEngine:
    """Test ScoringEngine class"""
    
    def test_engine_initialization(self):
        """Test scoring engine initialization"""
        engine = ScoringEngine()
        assert engine.findings == []
        assert engine.MAX_SCORE == 100
    
    def test_add_finding(self):
        """Test adding findings to engine"""
        engine = ScoringEngine()
        finding = Finding("T1", "r1", Severity.HIGH, "T", "d", "e", "r")
        
        engine.add_finding(finding)
        
        assert len(engine.findings) == 1
        assert engine.findings[0] == finding
    
    def test_calculate_risk_score_no_findings(self):
        """Test risk score calculation with no findings"""
        engine = ScoringEngine()
        score = engine.calculate_risk_score()
        
        assert score == 100
    
    def test_calculate_risk_score_with_findings(self):
        """Test risk score calculation with findings"""
        engine = ScoringEngine()
        
        # Add some findings
        engine.add_finding(Finding("C1", "r1", Severity.CRITICAL, "C", "d", "e", "r"))
        engine.add_finding(Finding("H1", "r2", Severity.HIGH, "H", "d", "e", "r"))
        engine.add_finding(Finding("M1", "r3", Severity.MEDIUM, "M", "d", "e", "r"))
        
        score = engine.calculate_risk_score()
        
        # 100 - (25 + 15 + 8) = 52
        assert score == 52
    
    def test_calculate_risk_score_minimum_zero(self):
        """Test that risk score never goes below zero"""
        engine = ScoringEngine()
        
        # Add findings that exceed 100 points
        for i in range(10):
            engine.add_finding(Finding(f"C{i}", f"r{i}", Severity.CRITICAL, "C", "d", "e", "r"))
        
        score = engine.calculate_risk_score()
        
        # Should be 0, not negative
        assert score == 0
    
    def test_get_risk_level_secure(self):
        """Test risk level for secure score"""
        engine = ScoringEngine()
        level, color = engine.get_risk_level(85)
        
        assert level == "Güvenli"
        assert color == "#4CAF50"
    
    def test_get_risk_level_medium(self):
        """Test risk level for medium risk score"""
        engine = ScoringEngine()
        level, color = engine.get_risk_level(65)
        
        assert level == "Orta Risk"
        assert color == "#FFC107"
    
    def test_get_risk_level_high(self):
        """Test risk level for high risk score"""
        engine = ScoringEngine()
        level, color = engine.get_risk_level(30)
        
        assert level == "Yüksek Risk"
        assert color == "#D32F2F"
    
    def test_get_summary(self):
        """Test findings summary"""
        engine = ScoringEngine()
        
        engine.add_finding(Finding("C1", "r1", Severity.CRITICAL, "C", "d", "e", "r"))
        engine.add_finding(Finding("C2", "r2", Severity.CRITICAL, "C", "d", "e", "r"))
        engine.add_finding(Finding("H1", "r3", Severity.HIGH, "H", "d", "e", "r"))
        engine.add_finding(Finding("M1", "r4", Severity.MEDIUM, "M", "d", "e", "r"))
        engine.add_finding(Finding("L1", "r5", Severity.LOW, "L", "d", "e", "r"))
        
        summary = engine.get_summary()
        
        assert summary['total_findings'] == 5
        assert summary['critical'] == 2
        assert summary['high'] == 1
        assert summary['medium'] == 1
        assert summary['low'] == 1
        assert summary['total_points'] == 76  # 25*2 + 15 + 8 + 3
    
    def test_get_quick_wins(self):
        """Test getting quick wins (low severity first)"""
        engine = ScoringEngine()
        
        engine.add_finding(Finding("H1", "r1", Severity.HIGH, "H", "d", "e", "r"))
        engine.add_finding(Finding("L1", "r2", Severity.LOW, "L", "d", "e", "r"))
        engine.add_finding(Finding("M1", "r3", Severity.MEDIUM, "M", "d", "e", "r"))
        
        quick_wins = engine.get_quick_wins(limit=2)
        
        assert len(quick_wins) == 2
        assert quick_wins[0].severity == Severity.LOW
        assert quick_wins[1].severity == Severity.MEDIUM
    
    def test_get_high_impact_fixes(self):
        """Test getting high impact fixes (high severity first)"""
        engine = ScoringEngine()
        
        engine.add_finding(Finding("H1", "r1", Severity.HIGH, "H", "d", "e", "r"))
        engine.add_finding(Finding("L1", "r2", Severity.LOW, "L", "d", "e", "r"))
        engine.add_finding(Finding("C1", "r3", Severity.CRITICAL, "C", "d", "e", "r"))
        
        high_impact = engine.get_high_impact_fixes(limit=2)
        
        assert len(high_impact) == 2
        assert high_impact[0].severity == Severity.CRITICAL
        assert high_impact[1].severity == Severity.HIGH
    
    def test_get_findings_by_severity(self):
        """Test filtering findings by severity"""
        engine = ScoringEngine()
        
        engine.add_finding(Finding("C1", "r1", Severity.CRITICAL, "C", "d", "e", "r"))
        engine.add_finding(Finding("H1", "r2", Severity.HIGH, "H", "d", "e", "r"))
        engine.add_finding(Finding("C2", "r3", Severity.CRITICAL, "C", "d", "e", "r"))
        
        critical_findings = engine.get_findings_by_severity(Severity.CRITICAL)
        
        assert len(critical_findings) == 2
        assert all(f.severity == Severity.CRITICAL for f in critical_findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])