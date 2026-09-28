# language: Python, file: backend/ai/anomaly_detector.py, target: Python 3.12
import json
import logging
from anthropic import AsyncAnthropic
from .brain import NexusState
from ..config import get_settings

logger = logging.getLogger(__name__)

ANOMALY_PROMPT = """You are a security researcher analyzing HTTP fuzzing responses for anomalies.

Tool that produced this output: {tool_name}
Response data sample:
{output_sample}

Analyze for:
1. Unusual response sizes (much larger/smaller than baseline)
2. Interesting status codes (500, 403 on specific paths, unusual redirects)
3. Time-based anomalies (slow responses suggesting blind SQLi/SSRF)
4. Error messages revealing stack traces, technology versions, internal paths
5. Reflected input (potential XSS/injection points)

Return JSON:
{{
  "anomalies_found": true/false,
  "findings": [
    {{
      "type": "size_anomaly|status_anomaly|time_anomaly|error_disclosure|reflection",
      "url": "...",
      "description": "...",
      "evidence": "...",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "follow_up_tool": "sqlmap|dalfox|ffuf|..."
    }}
  ],
  "suggested_next_tool": "...",
  "suggested_params": {{}}
}}"""


async def anomaly_detector_node(state: NexusState) -> NexusState:
    raw_outputs = state.get("raw_outputs", [])
    if not raw_outputs:
        return {**state, "anomaly_flagged": False}

    latest = raw_outputs[-1]
    tool_name = latest.get("tool", "unknown")
    job_id = latest.get("job_id")
    session_id = state["session_id"]

    output_sample = ""
    if job_id:
        try:
            with open(f"data/sessions/{session_id}/jobs/{job_id}.log") as f:
                lines = f.readlines()
                output_sample = "".join(lines[-100:])
        except FileNotFoundError:
            pass

    if not output_sample:
        return {**state, "anomaly_flagged": False}

    client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)
    try:
        response = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": ANOMALY_PROMPT.format(
                tool_name=tool_name,
                output_sample=output_sample[:4000],
            )}],
        )
        text = response.content[0].text
        start = text.find("{")
        end = text.rfind("}") + 1
        result = json.loads(text[start:end]) if start != -1 else {}
    except Exception as e:
        logger.error(f"anomaly_detector error: {e}")
        result = {"anomalies_found": False}

    new_findings = []
    for f in result.get("findings", []):
        new_findings.append({
            "title": f"Anomaly: {f.get('type', 'unknown')} at {f.get('url', '')}",
            "description": f.get("description", ""),
            "severity": f.get("severity", "INFO"),
            "evidence": f.get("evidence", ""),
            "affected_asset": f.get("url", state["target"]),
        })

    return {
        **state,
        "findings": state["findings"] + new_findings,
        "anomaly_flagged": False,  # reset flag after processing
        "anomaly_suggested_tool": result.get("suggested_next_tool"),
        "anomaly_suggested_params": result.get("suggested_params", {}),
    }
