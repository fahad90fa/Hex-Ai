EXECUTIVE_SUMMARY_PROMPT = """You are writing an executive summary for a penetration test report.

Target: {target}
Test duration: {duration}
Total findings: {total_findings}
Critical: {critical_count}
High: {high_count}
Medium: {medium_count}
Low: {low_count}
Top CVEs: {top_cves}
Attack chains discovered: {chains_discovered}

Write a professional executive summary (3-4 paragraphs) for a non-technical audience.
Focus on business risk, not technical details. Be direct and actionable."""

TECHNICAL_FINDING_PROMPT = """Write a detailed technical writeup for this finding.

Finding: {title}
Severity: {severity}
CVSS Score: {cvss_score}
Affected Asset: {affected_asset}
CVEs: {cve_ids}
Evidence: {evidence}

Write:
1. Technical description (2-3 paragraphs)
2. Impact analysis
3. Step-by-step reproduction steps
4. Remediation guidance (specific, actionable)

Be precise. Include exact commands, headers, payloads where relevant."""

REMEDIATION_PROMPT = """Generate specific remediation steps for this vulnerability.

Title: {title}
Severity: {severity}
Affected Asset: {affected_asset}
Description: {description}
Tech Stack: {tech_stack}

Provide:
1. Immediate mitigations (can apply today)
2. Long-term fix
3. Verification steps (how to confirm the fix worked)
4. Estimated effort: Low/Medium/High"""
