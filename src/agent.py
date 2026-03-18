from dotenv import load_dotenv
load_dotenv()

from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver
from langsmith import traceable
from src.tools import generate_diagram, generate_checklist, generate_threat_model, analyze_manifest

llm = ChatOllama(model="llama3.2", temperature=0.0)
tools = [generate_diagram, generate_checklist, generate_threat_model, analyze_manifest]
memory = MemorySaver()

SYSTEM_PROMPT = """You are a CKS Kubernetes security architect agent.

When a user asks for a diagram, checklist, or threat model:
1. Call the appropriate tool
2. Return the tool's output EXACTLY as-is — do not summarize, rephrase, or add explanation
3. If multiple artifacts are requested, call each tool and return all outputs separated by a blank line

When a user provides a YAML manifest (contains 'apiVersion:' or 'kind:'):
- Call analyze_manifest with the full YAML content as the argument

You have memory of the current session. If the user says 'now do X' or 'change it to Y',
use the context of previous messages to understand what they are referring to."""

agent = create_react_agent(llm, tools, prompt=SYSTEM_PROMPT, checkpointer=memory)


def _config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


@traceable(name="cks-agent-run")
def run_agent(query: str, thread_id: str = "default") -> str:
    from langchain_core.messages import ToolMessage
    result = agent.invoke({"messages": [("human", query)]}, config=_config(thread_id))
    tool_outputs = [m.content for m in result["messages"] if isinstance(m, ToolMessage)]
    if tool_outputs:
        return "\n\n".join(tool_outputs)
    return result["messages"][-1].content


@traceable(name="cks-agent-stream")
def stream_agent(query: str, thread_id: str = "default") -> str:
    """Stream tool output tokens to stdout as they are generated. Returns the full result."""
    from langchain_core.messages import AIMessageChunk, ToolMessage
    tool_outputs = []

    for chunk, metadata in agent.stream(
        {"messages": [("human", query)]},
        config=_config(thread_id),
        stream_mode="messages",
    ):
        node = metadata.get("langgraph_node", "")
        if isinstance(chunk, AIMessageChunk) and node == "tools" and chunk.content:
            print(chunk.content, end="", flush=True)
        elif isinstance(chunk, ToolMessage):
            tool_outputs.append(chunk.content)

    print()
    return "\n\n".join(tool_outputs) if tool_outputs else ""
