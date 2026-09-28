# language: Python, file: backend/ai/result_analyzer.py, target: Python 3.12
import asyncio
import json
import logging
from anthropic import AsyncAnthropic
from .brain import NexusState
from ..config import get_settings

logger = logging.getLogger(__name__)

ANALYZER_PROMPT = """You are an expert penetration tester parsing raw tool output.

Tool: {tool_name}
Raw output (last 200 lines):
{output}

Extract structured information:
- Subdomains discovered
- IP addresses
- Open ports and services (with versions)
- Technologies/frameworks
- Potential vulnerabilities
- Credentials found
- Interesting URLs/endpoints
- Anomalies (unusual response sizes, status codes, timeouts)

Return JSON:
{{
  "subdomains": ["..."],
  "ips": ["..."],
  "services": [{{"host": "...", "port": 0, "service": "...", "version": "...", "banner": "..."}}],
  "technologies": [{{"name": "...", "version": "...", "confidence": 0.0}}],
  "findings": [{{"title": "...", "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL", "description": "...", "evidence": "...", "affected_asset": "..."}}],
  "endpoints": ["..."],
  "anomalies": [{{"type": "...", "description": "...", "evidence": "..."}}],
  "needs_followup": true/false,
  "suggested_tools": ["..."]
}}"""


async def result_analyzer_node(state: NexusState) -> NexusState:
    if not state.get("current_job_id") or not state.get("current_tool"):
        return {**state, "iteration": state["iteration"] + 1}

    session_id = state["session_id"]
    job_id = state["current_job_id"]
    tool_name = state["current_tool"]

    # wait for job to complete (poll Redis for job.completed event)
    from ..core.orchestrator import get_orchestrator
    import redis.asyncio as aioredis

    redis = await aioredis.from_url(get_settings().redis_url, decode_responses=True)
    log_path = f"data/sessions/{session_id}/jobs/{job_id}.log"

    # wait up to 5 minutes for job output
    for _ in range(300):
        raw = await redis.get(f"nexus:job:{job_id}:status")
        if raw in ("COMPLETED", "FAILED"):
            break
        await asyncio.sleep(1)

    # read output from log file
    output_lines = []
    try:
        with open(log_path) as f:
            output_lines = f.readlines()[-200:]
    except FileNotFoundError:
        pass

    if not output_lines:
        return {**state, "iteration": state["iteration"] + 1}

    output = "".join(output_lines)
    client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)

    try:
        response = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=2048,
            messages=[{"role": "user", "content": ANALYZER_PROMPT.format(
                tool_name=tool_name,
                output=output[:8000],
            )}],
        )
        text = response.content[0].text
        start = text.find("{")
        end = text.rfind("}") + 1
        parsed = json.loads(text[start:end]) if start != -1 else {}
    except Exception as e:
        logger.error(f"result_analyzer error: {e}")
        parsed = {}

    new_services = parsed.get("services", [])
    new_findings = parsed.get("findings", [])
    anomaly_flagged = bool(parsed.get("anomalies"))

    # add graph nodes for discovered subdomains/services
    graph_nodes = []
    for sub in parsed.get("subdomains", []):
        graph_nodes.append({"type": "SUBDOMAIN", "label": sub, "properties": {}})
    for svc in new_services:
        graph_nodes.append({"type": "SERVICE", "label": f"{svc.get('host')}:{svc.get('port')}/{svc.get('service')}", "properties": svc})
    for ep in parsed.get("endpoints", []):
        graph_nodes.append({"type": "ENDPOINT", "label": ep, "properties": {}})

    # update graph engine
    if graph_nodes:
        try:
            from ..core.graph_engine import get_graph_engine
            ge = get_graph_engine()
            for node_data in graph_nodes:
                await ge.add_node(session_id, node_data["type"], node_data["label"], node_data["properties"])
        except Exception as e:
            logger.error(f"graph update error: {e}")

    return {
        **state,
        "services": state["services"] + new_services,
        "findings": state["findings"] + new_findings,
        "graph_nodes": state["graph_nodes"] + graph_nodes,
        "anomaly_flagged": anomaly_flagged,
        "raw_outputs": state["raw_outputs"] + [{"tool": tool_name, "job_id": job_id}],
        "iteration": state["iteration"] + 1,
    }
