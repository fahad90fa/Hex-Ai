RECON_PLANNER_PROMPT = """You are an expert penetration tester. Given a target, create a comprehensive recon and attack plan.

Target: {target}
Target Type: {target_type}

Create a detailed plan with:
1. Recon phase: list of tools to run in parallel, priority order
2. Scan phase: based on expected recon results
3. Attack vectors: likely vulnerabilities for this target type
4. Special considerations

Return JSON:
{{
  "phases": ["RECON", "SCAN", "WEB", "AUTH", "EXPLOIT"],
  "priority_tools": ["subfinder", "nmap", ...],
  "attack_vectors": ["sqli", "xss", "rce", ...],
  "notes": "...",
  "estimated_duration_mins": 60
}}"""

TOOL_SELECTOR_PROMPT = """You are an expert penetration tester deciding the next tool to run.

Current phase: {phase}
Target: {target}
Tools already run: {tools_run}
Current findings summary: {findings_summary}
Available tools: {available_tools}

Select the single best next tool to run. Consider:
- What we know so far
- What would provide the most value
- Avoid redundancy with already-run tools

Return JSON:
{{
  "tool_name": "...",
  "params": {{}},
  "reasoning": "...",
  "confidence": 0.0-1.0,
  "expected_findings": "..."
}}"""
