# language: Python, file: backend/ai/tool_selector.py
import json
import logging
from anthropic import AsyncAnthropic
from .brain import NexusState
from .prompts.recon import TOOL_SELECTOR_PROMPT
from ..config import get_settings
from ..tools import TOOL_REGISTRY

logger = logging.getLogger(__name__)


async def tool_selector_node(state: NexusState) -> NexusState:
    available = [t for t in TOOL_REGISTRY.keys() if t not in state["tools_run"]]
    if not available:
        return {**state, "should_stop": True}

    findings_summary = f"{len(state['findings'])} findings, {len(state['services'])} services detected"
    client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)

    prompt = TOOL_SELECTOR_PROMPT.format(
        phase=state["phase"],
        target=state["target"],
        tools_run=state["tools_run"][-10:],
        findings_summary=findings_summary,
        available_tools=available[:30],
    )

    try:
        response = await client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text
        start = text.find("{")
        end = text.rfind("}") + 1
        selection = json.loads(text[start:end])
        tool_name = selection.get("tool_name", available[0])
        params = selection.get("params", {})
        confidence = float(selection.get("confidence", 0.7))
        reasoning = selection.get("reasoning", "")
    except Exception as e:
        logger.error(f"tool_selector error: {e}")
        tool_name = available[0]
        params = {"target": state["target"]}
        confidence = 0.5
        reasoning = "fallback selection"

    # inject target if not in params
    if "target" not in params:
        params["target"] = state["target"]

    # dispatch via orchestrator
    from ..core.orchestrator import get_orchestrator
    orch = get_orchestrator()
    job_id = await orch.dispatch({
        "session_id": state["session_id"],
        "tool_name": tool_name,
        "params": params,
    })

    decision = {
        "node": "tool_selector",
        "tool": tool_name,
        "params": params,
        "reasoning": reasoning,
        "confidence": confidence,
        "job_id": job_id,
    }

    return {
        **state,
        "current_tool": tool_name,
        "current_job_id": job_id,
        "tools_run": state["tools_run"] + [tool_name],
        "decisions": state["decisions"] + [decision],
        "iteration": state["iteration"] + 1,
    }
