# language: Python, file: backend/ai/planner.py
import json
import logging
from anthropic import AsyncAnthropic
from .brain import NexusState, Phase
from .prompts.recon import RECON_PLANNER_PROMPT
from ..config import get_settings

logger = logging.getLogger(__name__)
_client: AsyncAnthropic | None = None


def _get_client() -> AsyncAnthropic:
    global _client
    if _client is None:
        _client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)
    return _client


async def planner_node(state: NexusState) -> NexusState:
    target = state["target"]
    target_type = "domain" if "." in target and not target.replace(".", "").isdigit() else "ip"

    prompt = RECON_PLANNER_PROMPT.format(target=target, target_type=target_type)
    try:
        response = await _get_client().messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text
        # extract JSON block
        start = text.find("{")
        end = text.rfind("}") + 1
        plan = json.loads(text[start:end]) if start != -1 else {
            "priority_tools": ["subfinder", "nmap"],
            "phases": ["RECON", "SCAN"],
        }
    except Exception as e:
        logger.error(f"planner error: {e}")
        plan = {
            "priority_tools": ["subfinder", "nmap", "nuclei"],
            "phases": ["RECON", "SCAN", "WEB"],
        }

    decision = {
        "node": "planner",
        "action": "built_attack_plan",
        "plan_summary": plan.get("notes", ""),
        "priority_tools": plan.get("priority_tools", []),
    }

    return {
        **state,
        "plan": plan,
        "phase": Phase.RECON,
        "decisions": state["decisions"] + [decision],
    }
