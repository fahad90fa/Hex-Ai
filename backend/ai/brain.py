# language: Python, file: backend/ai/brain.py, target: Python 3.12
# LangGraph state machine orchestrating the full pentest AI brain
import asyncio
import logging
from typing import TypedDict, Annotated, Optional
from enum import Enum
import operator

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .planner import planner_node
from .tool_selector import tool_selector_node
from .result_analyzer import result_analyzer_node
from .cve_matcher import cve_matcher_node
from .chain_builder import chain_builder_node
from .payload_factory import payload_factory_node
from .anomaly_detector import anomaly_detector_node
from .report_writer import report_writer_node

logger = logging.getLogger(__name__)


class Phase(str, Enum):
    PLANNING = "PLANNING"
    RECON = "RECON"
    SCAN = "SCAN"
    WEB = "WEB"
    AUTH = "AUTH"
    EXPLOIT = "EXPLOIT"
    REPORT = "REPORT"
    DONE = "DONE"


class NexusState(TypedDict):
    session_id: str
    target: str
    phase: Phase
    plan: Optional[dict]
    tools_run: Annotated[list[str], operator.add]
    current_tool: Optional[str]
    current_job_id: Optional[str]
    raw_outputs: Annotated[list[dict], operator.add]
    findings: Annotated[list[dict], operator.add]
    services: Annotated[list[dict], operator.add]
    cve_matches: Annotated[list[dict], operator.add]
    exploit_chains: Annotated[list[dict], operator.add]
    graph_nodes: Annotated[list[dict], operator.add]
    decisions: Annotated[list[dict], operator.add]
    iteration: int
    error: Optional[str]
    should_stop: bool
    anomaly_flagged: bool


def route_after_analyzer(state: NexusState) -> str:
    if state.get("should_stop"):
        return "report_writer"
    if state.get("services"):
        return "cve_matcher"
    if state.get("anomaly_flagged"):
        return "anomaly_detector"
    if state["iteration"] > 50:
        return "report_writer"
    return "tool_selector"


def route_after_cve_matcher(state: NexusState) -> str:
    if state.get("cve_matches") and any(m.get("exploitable") for m in state["cve_matches"]):
        return "chain_builder"
    return "tool_selector"


def route_after_chain_builder(state: NexusState) -> str:
    if state.get("exploit_chains"):
        return "payload_factory"
    return "report_writer"


def route_after_payload_factory(state: NexusState) -> str:
    return "report_writer"


def route_after_anomaly(state: NexusState) -> str:
    return "tool_selector"


def build_graph() -> StateGraph:
    workflow = StateGraph(NexusState)

    workflow.add_node("planner", planner_node)
    workflow.add_node("tool_selector", tool_selector_node)
    workflow.add_node("result_analyzer", result_analyzer_node)
    workflow.add_node("cve_matcher", cve_matcher_node)
    workflow.add_node("chain_builder", chain_builder_node)
    workflow.add_node("payload_factory", payload_factory_node)
    workflow.add_node("anomaly_detector", anomaly_detector_node)
    workflow.add_node("report_writer", report_writer_node)

    workflow.set_entry_point("planner")
    workflow.add_edge("planner", "tool_selector")
    workflow.add_edge("tool_selector", "result_analyzer")
    workflow.add_conditional_edges("result_analyzer", route_after_analyzer, {
        "tool_selector": "tool_selector",
        "cve_matcher": "cve_matcher",
        "anomaly_detector": "anomaly_detector",
        "report_writer": "report_writer",
    })
    workflow.add_conditional_edges("cve_matcher", route_after_cve_matcher, {
        "chain_builder": "chain_builder",
        "tool_selector": "tool_selector",
    })
    workflow.add_conditional_edges("chain_builder", route_after_chain_builder, {
        "payload_factory": "payload_factory",
        "report_writer": "report_writer",
    })
    workflow.add_conditional_edges("payload_factory", route_after_payload_factory, {
        "report_writer": "report_writer",
    })
    workflow.add_conditional_edges("anomaly_detector", route_after_anomaly, {
        "tool_selector": "tool_selector",
    })
    workflow.add_edge("report_writer", END)

    return workflow


async def run_session(session_id: str, target: str) -> NexusState:
    graph = build_graph().compile(checkpointer=MemorySaver())
    initial_state: NexusState = {
        "session_id": session_id,
        "target": target,
        "phase": Phase.PLANNING,
        "plan": None,
        "tools_run": [],
        "current_tool": None,
        "current_job_id": None,
        "raw_outputs": [],
        "findings": [],
        "services": [],
        "cve_matches": [],
        "exploit_chains": [],
        "graph_nodes": [],
        "decisions": [],
        "iteration": 0,
        "error": None,
        "should_stop": False,
        "anomaly_flagged": False,
    }
    config = {"configurable": {"thread_id": session_id}}
    final_state = await graph.ainvoke(initial_state, config=config)
    return final_state
