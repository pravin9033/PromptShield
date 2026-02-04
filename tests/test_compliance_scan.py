from promptshield import scan_output


def test_compliance_detects_email():
    result = scan_output("Contact me at jane@example.com")
    assert result.category in {"PII", "SECRETS", "NONE"}
    assert result.risk_score >= 0
    assert any(issue.matches for issue in result.issues)
