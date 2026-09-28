# language: Python, file: backend/ai/chain_builder.py, target: Python 3.12
import json
import logging
from anthropic import AsyncAnthropic
from .brain import NexusState
from .prompts.exploit import CHAIN_BUILDER_PROMPT
from ..config import get_settings

logger = logging.getLogger(__name__)


async def chain_builder_node(state: NexusState) -> NexusState:
    exploitable = [m for m in state.get("cve_matches", []) if m.get("exploitable")]
    if not exploitable:
        return {**state, "should_stop": True}

    client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)
    chains = []

    for match in exploitable[:3]:  # build chains for top 3 exploitable CVEs
        try:
            prompt = CHAIN_BUILDER_PROMPT.format(
                cve_id=match.get("cve_id"),
                target=state["target"],
                service=match.get("service"),
                version=match.get("version"),
                context=f"Chain steps from assessment: {match.get('chain_steps', [])}",
            )
            response = await client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text
            start = text.find("{")
            end = text.rfind("}") + 1
            chain = json.loads(text[start:end]) if start != -1 else {}
            chain["cve_id"] = match.get("cve_id")
            chains.append(chain)
            logger.info(f"built chain for {match.get('cve_id')}: {len(chain.get('steps', []))} steps")
        except Exception as e:
            logger.error(f"chain_builder error: {e}")

    return {**state, "exploit_chains": state["exploit_chains"] + chains}
