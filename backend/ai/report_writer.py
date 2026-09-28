# language: Python, file: backend/ai/report_writer.py, target: Python 3.12
import logging
from anthropic import AsyncAnthropic
from .brain import NexusState
from .prompts.report import EXECUTIVE_SUMMARY_PROMPT, TECHNICAL_FINDING_PROMPT
from ..config import get_settings

logger = logging.getLogger(__name__)


async def report_writer_node(state: NexusState) -> NexusState:
    findings = state.get("findings", [])
    session_id = state["session_id"]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)

    # executive summary
    exec_summary = ""
    try:
        top_cves = [m.get("cve_id") for m in state.get("cve_matches", [])[:5]]
        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            target=state["target"],
            duration="N/A",
            total_findings=len(findings),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            top_cves=", ".join(top_cves) or "None",
            chains_discovered=len(state.get("exploit_chains", [])),
        )
        response = await client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        exec_summary = response.content[0].text
    except Exception as e:
        logger.error(f"executive summary error: {e}")
        exec_summary = f"Penetration test of {state['target']} completed with {len(findings)} findings."

    # technical writeups for HIGH+ findings
    technical_writeups = []
    for finding in [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")][:10]:
        try:
            prompt = TECHNICAL_FINDING_PROMPT.format(
                title=finding.get("title", ""),
                severity=finding.get("severity", ""),
                cvss_score=finding.get("cvss_score", 0),
                affected_asset=finding.get("affected_asset", ""),
                cve_ids=finding.get("cve_ids", []),
                evidence=finding.get("evidence", "")[:500],
            )
            resp = await client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            technical_writeups.append({
                "finding_title": finding.get("title"),
                "writeup": resp.content[0].text,
            })
        except Exception as e:
            logger.error(f"technical writeup error: {e}")

    # trigger report generation
    try:
        from ..core.report_gen import get_report_gen
        gen = get_report_gen()
        report = await gen.generate(
            session_id=session_id,
            template="technical",
            exec_summary=exec_summary,
            findings=findings,
            writeups=technical_writeups,
        )

        from ..core.ws_hub import get_hub
        await get_hub().broadcast(session_id, "report.ready", {
            "report_id": str(report.id) if hasattr(report, "id") else "report",
            "pdf_path": report.pdf_path if hasattr(report, "pdf_path") else "",
            "html_path": report.html_path if hasattr(report, "html_path") else "",
        })
    except Exception as e:
        logger.error(f"report gen error: {e}")

    return {**state, "should_stop": True}
