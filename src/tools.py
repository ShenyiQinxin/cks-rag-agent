import re
import yaml
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langsmith import traceable
from src.vectorstore import get_retriever

llm = ChatOllama(model="llama3.2", temperature=0.0)
parser = StrOutputParser()


@traceable(name="faiss-retrieve")
def _get_context(topic: str, k: int = 4) -> str:
    retriever = get_retriever(k=k)
    docs = retriever.invoke(topic)
    return "\n\n".join(doc.page_content for doc in docs)


def _clean_mermaid(text: str) -> str:
    """Strip markdown fences if the LLM wrapped output in ```mermaid ... ```."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # drop opening fence line and closing fence line
        inner = [l for l in lines[1:] if not l.strip().startswith("```")]
        text = "\n".join(inner).strip()
    return text


def _validate_mermaid(text: str) -> tuple[bool, str]:
    """Return (is_valid, reason). Checks structural correctness only."""
    text = text.strip()
    if text.startswith("graph TD") or text.startswith("graph LR"):
        if "-->" not in text and "---" not in text:
            return False, "graph TD has no edges"
        if text.count("[") != text.count("]"):
            return False, "unmatched brackets in node labels"
        if re.search(r"\[[^\]]*\[", text):
            return False, "unmatched brackets in node labels"
        return True, ""
    if text.startswith("sequenceDiagram"):
        if "->>" not in text and "-->" not in text:
            return False, "sequenceDiagram has no messages"
        return True, ""
    return False, f"output does not start with a known Mermaid keyword: {text[:40]!r}"


def _invoke_with_mermaid_retry(chain, inputs: dict, strict_note: str) -> str:
    """Invoke chain, clean fences, validate, retry once with stricter note if invalid."""
    result = _clean_mermaid((chain).invoke(inputs))
    ok, reason = _validate_mermaid(result)
    if not ok:
        retry_inputs = dict(inputs)
        # append a correction note to the human message key (last value in inputs)
        human_key = list(retry_inputs.keys())[-1]
        retry_inputs[human_key] = retry_inputs[human_key] + f"\n\nIMPORTANT: Previous attempt failed validation ({reason}). {strict_note}"
        result = _clean_mermaid(chain.invoke(retry_inputs))
    return result


@traceable(name="faiss-retrieve-with-sources")
def _get_context_with_sources(topic: str, k: int = 4) -> tuple[str, list[int]]:
    """Return (context, pages) where context has [p.N] prefix on each chunk."""
    retriever = get_retriever(k=k)
    docs = retriever.invoke(topic)
    pages = sorted({doc.metadata.get("page", 0) + 1 for doc in docs})
    context = "\n\n".join(
        f"[p.{doc.metadata.get('page', 0) + 1}] {doc.page_content}" for doc in docs
    )
    return context, pages


def _extract_security_summary(yaml_content: str) -> dict:
    """Parse a Kubernetes YAML manifest and return a structured security summary."""
    try:
        manifest = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return {"kind": "Unknown", "name": "unknown", "risks": [], "controls": [], "summary": str(e), "rag_query": "kubernetes security"}

    if not isinstance(manifest, dict):
        return {"kind": "Unknown", "name": "unknown", "risks": [], "controls": [],
                "summary": "Input is not a valid Kubernetes manifest.", "rag_query": "kubernetes security"}

    kind = manifest.get("kind", "Unknown")
    meta = manifest.get("metadata", {})
    name = meta.get("name", "unnamed")
    namespace = meta.get("namespace", "default")
    spec = manifest.get("spec", {})

    # Resolve pod spec — works for Pod, Deployment, DaemonSet, StatefulSet
    pod_spec = spec.get("template", {}).get("spec", spec) if kind != "Pod" else spec

    risks = []
    controls = []

    # Pod-level flags
    if pod_spec.get("hostPID"):
        risks.append("hostPID: true — shares host process namespace")
    if pod_spec.get("hostNetwork"):
        risks.append("hostNetwork: true — bypasses network isolation")
    if pod_spec.get("hostIPC"):
        risks.append("hostIPC: true — shares host IPC namespace")

    sa = pod_spec.get("serviceAccountName", "default")
    if sa == "default":
        risks.append("serviceAccountName: default — overprivileged default SA")
    else:
        controls.append(f"serviceAccountName: {sa}")

    # Pod-level securityContext
    psc = pod_spec.get("securityContext", {})
    if psc.get("runAsNonRoot"):
        controls.append("runAsNonRoot: true")
    else:
        risks.append("runAsNonRoot not set — container may run as root")
    if psc.get("seccompProfile"):
        controls.append(f"seccompProfile: {psc['seccompProfile'].get('type')}")
    else:
        risks.append("seccompProfile not set — use RuntimeDefault")

    # Container-level
    for c in pod_spec.get("containers", []):
        cname = c.get("name", "container")
        csc = c.get("securityContext", {})

        if csc.get("privileged"):
            risks.append(f"{cname}: privileged: true — full host access")
        if csc.get("allowPrivilegeEscalation", True):
            risks.append(f"{cname}: allowPrivilegeEscalation not disabled")
        else:
            controls.append(f"{cname}: allowPrivilegeEscalation: false")
        if csc.get("readOnlyRootFilesystem"):
            controls.append(f"{cname}: readOnlyRootFilesystem: true")
        else:
            risks.append(f"{cname}: readOnlyRootFilesystem not set")

        caps = csc.get("capabilities", {})
        added = caps.get("add", [])
        dropped = caps.get("drop", [])
        if added:
            risks.append(f"{cname}: capabilities added: {', '.join(added)}")
        if "ALL" in dropped:
            controls.append(f"{cname}: capabilities drop ALL")
        elif not dropped:
            risks.append(f"{cname}: no capabilities dropped")

        if c.get("image", "").endswith(":latest"):
            risks.append(f"{cname}: image tag ':latest' — unpinned image")

    # Volumes
    for v in pod_spec.get("volumes", []):
        if "hostPath" in v:
            risks.append(f"volume '{v['name']}': hostPath mount — host filesystem access")

    # NetworkPolicy
    if kind == "NetworkPolicy":
        ingress = spec.get("ingress")
        egress = spec.get("egress")
        if ingress is None:
            risks.append("No ingress rules — all ingress blocked by default")
        if egress is None:
            risks.append("No egress rules — all egress blocked by default")

    rag_query = f"kubernetes {kind} security hardening {' '.join(['securityContext', 'capabilities', 'RBAC', 'hostPID', 'privileged'] if risks else ['best practices'])}"

    summary_lines = [
        f"Kind: {kind}  Name: {name}  Namespace: {namespace}",
        "",
        "SECURITY RISKS FOUND:" if risks else "No risks found.",
        *[f"  - {r}" for r in risks],
        "",
        "SECURITY CONTROLS CONFIGURED:" if controls else "No controls configured.",
        *[f"  + {c}" for c in controls],
    ]

    return {
        "kind": kind,
        "name": name,
        "namespace": namespace,
        "risks": risks,
        "controls": controls,
        "summary": "\n".join(summary_lines),
        "rag_query": rag_query,
    }


@tool
def generate_diagram(topic: str) -> str:
    """Generate a Mermaid architecture diagram for a Kubernetes security topic."""
    context = _get_context(topic)
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Kubernetes security architect. Output only a valid Mermaid flowchart using graph TD syntax.

Rules:
- Use ONLY graph TD syntax: nodes like A[Label] and edges like A --> B
- Do NOT use participant, ->>, or sequenceDiagram syntax
- Keep it to 8-12 nodes maximum
- No explanation, no markdown fences, just the raw Mermaid code
- Show architectural layers with branching — do NOT draw a single linear chain
- Group related security controls as parallel branches off a central component
- Use subgraphs to separate logical layers (e.g. Auth, Network, Runtime)

Example of correct branching architecture:
graph TD
    A[Client] --> B[API Server]
    subgraph Auth
        B --> C[RBAC Check]
        B --> D[mTLS Verify]
    end
    subgraph Runtime
        B --> E[Admission Controller]
        E --> F[Pod Security Admission]
        E --> G[OPA Gatekeeper]
    end
    C -->|denied| H[403 Forbidden]
    F -->|violation| H"""),
        ("human", "Context:\n{context}\n\nGenerate a Mermaid graph TD architecture diagram for: {topic}")
    ])
    chain = prompt | llm | parser
    return _invoke_with_mermaid_retry(
        chain,
        {"context": context, "topic": topic},
        "Output ONLY raw Mermaid starting with 'graph TD' on line 1. No fences, no explanation.",
    )


@tool
def generate_checklist(topic: str) -> str:
    """Generate a hardening checklist as a markdown table for a Kubernetes security topic."""
    context, pages = _get_context_with_sources(topic)
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Kubernetes security expert. Output a markdown table with columns: | Control | Description | Priority | Source |. No explanation, only the table followed by one footer line.

Rules:
- Control names must be concise (2-4 words), no numbering
- All recommendations must follow security best practices
- Never recommend logging sensitive data, storing secrets in plaintext, or disabling security features
- Priority must be one of: Critical / High / Medium
- Minimum 6 rows, maximum 12 rows
- Source column: cite the page label(s) from the context that informed that row, e.g. p.23 or p.23, p.45
- After the table, add exactly one line: **Source:** LFS260 Kubernetes Security Labs — pp. {pages}"""),
        ("human", "Context:\n{context}\n\nGenerate a hardening checklist for: {topic}")
    ])
    pages_str = ", ".join(str(p) for p in pages)
    return (prompt | llm | parser).invoke({"context": context, "topic": topic, "pages": pages_str})


@tool
def generate_threat_model(topic: str) -> str:
    """Generate a Mermaid threat model sequence diagram for a Kubernetes security topic."""
    context = _get_context(topic)
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Kubernetes security architect. Output only a valid Mermaid sequence diagram showing threat vectors and mitigations.

Rules:
- Start with: sequenceDiagram
- Use participants: Attacker, a target Component, and a Defender/control
- Show: attack attempt → detection/block → mitigation
- The FINAL step must always show the attack blocked or mitigated — never end on a successful unmitigated attack
- Maximum 10 sequence steps total
- Do NOT repeat any line or Note
- No explanation, no markdown fences, just the raw Mermaid code

Example of correct syntax (note: ends with block/mitigation):
sequenceDiagram
    participant A as Attacker
    participant E as etcd
    participant D as TLS Guard
    A->>E: Connect without cert
    D->>A: Reject: cert required
    Note over E,D: mTLS enforced on port 2379
    A->>E: Connect with stolen cert
    D->>A: Reject: cert revoked (CRL check)
    Note over D: Rotate etcd certs immediately"""),
        ("human", "Context:\n{context}\n\nGenerate a threat model sequence diagram for: {topic}")
    ])
    chain = prompt | llm | parser
    return _invoke_with_mermaid_retry(
        chain,
        {"context": context, "topic": topic},
        "Output ONLY raw Mermaid starting with 'sequenceDiagram' on line 1. No fences, no explanation.",
    )


@tool
def analyze_manifest(yaml_content: str) -> str:
    """Analyze a Kubernetes YAML manifest and generate a security diagram showing configured controls, risks, and recommended mitigations."""
    parsed = _extract_security_summary(yaml_content)
    context = _get_context(parsed["rag_query"])
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Kubernetes security architect performing a security posture review.
You will receive a structured security summary of a Kubernetes manifest and CKS documentation context.
Output only a valid Mermaid flowchart using graph TD syntax.

Rules:
- Use ONLY graph TD syntax
- Show the resource hierarchy: Kind → Pod → Container(s)
- Use subgraphs to group: Risks, Controls, Mitigations
- ONLY include items explicitly listed under SECURITY RISKS in the Risks subgraph
- ONLY include items explicitly listed under SECURITY CONTROLS in the Controls subgraph
- Do NOT invent, assume, or add any control that is not listed in the summary
- If the summary says "No controls configured" then omit the Controls subgraph entirely
- For each risk node add one mitigation edge — no square brackets inside node labels
- 10-18 nodes maximum
- No explanation, no markdown fences, just the raw Mermaid code

Example:
graph TD
    A[Deployment: my-app] --> B[Pod]
    B --> C[Container: app]
    subgraph Risks
        C --> R1[RISK: privileged true]
        C --> R2[RISK: hostPID enabled]
    end
    subgraph Mitigations
        R1 --> M1[Set privileged false]
        R2 --> M2[Remove hostPID]
    end"""),
        ("human", "CKS Context:\n{context}\n\nManifest Security Summary:\n{summary}\n\nGenerate a security posture diagram for this {kind} manifest.")
    ])
    chain = prompt | llm | parser
    return _invoke_with_mermaid_retry(
        chain,
        {"context": context, "summary": parsed["summary"], "kind": parsed["kind"]},
        "Output ONLY raw Mermaid starting with 'graph TD' on line 1. No fences, no explanation.",
    )
