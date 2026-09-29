# language: Python, file: backend/ai/cve_matcher.py, target: Python 3.12
import json
import logging
from anthropic import AsyncAnthropic
from .brain import NexusState
from .prompts.exploit import CVE_ASSESSMENT_PROMPT
from ..config import get_settings
from ..core.cve_feed import get_cve_feed

logger = logging.getLogger(__name__)


async def cve_matcher_node(state: NexusState) -> NexusState:
    services = state.get("services", [])
    if not services:
        return state

    client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)
    cve_feed = get_cve_feed()
    cve_matches = []

    for svc in services:
        service_name = svc.get("service", "")
        version = svc.get("version", "")
        if not service_name or not version:
            continue

        keyword = f"{service_name} {version}"
        try:
            cves = await cve_feed.search_cve(keyword=keyword)
        except Exception as e:
            logger.error(f"cve_feed error for {keyword}: {e}")
            continue

        for cve in cves[:5]:  # top 5 CVEs per service
            try:
                prompt = CVE_ASSESSMENT_PROMPT.format(
                    service=service_name,
                    version=version,
                    cve_id=cve.cve_id,
                    cve_description=cve.description[:500],
                    cvss_score=cve.cvss_score,
                    context=f"Target: {state['target']}",
                )
                response = await client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = response.content[0].text
                start = text.find("{")
                end = text.rfind("}") + 1
                assessment = json.loads(text[start:end]) if start != -1 else {}
                assessment["cve_id"] = cve.cve_id
                assessment["cvss_score"] = cve.cvss_score
                assessment["service"] = service_name
                assessment["version"] = version
                assessment["has_exploit"] = cve.has_exploit
                cve_matches.append(assessment)

                # broadcast event
                from ..core.ws_hub import get_hub
                await get_hub().broadcast(state["session_id"], "cve.match", {
                    "cve_id": cve.cve_id,
                    "service": service_name,
                    "severity": "CRITICAL" if cve.cvss_score >= 9.0 else "HIGH" if cve.cvss_score >= 7.0 else "MEDIUM",
                    "has_exploit": cve.has_exploit,
                    "exploitable": assessment.get("exploitable", False),
                })
            except Exception as e:
                logger.error(f"cve assessment error: {e}")

    return {**state, "cve_matches": state["cve_matches"] + cve_matches}
