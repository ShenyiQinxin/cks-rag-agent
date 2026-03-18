"""
Integration tests for the CKS agent tools and pipeline.
Requires Ollama running locally with llama3.2.
"""
import pytest
from pathlib import Path
from src.tools import generate_diagram, generate_checklist, generate_threat_model, analyze_manifest, _extract_security_summary, _clean_mermaid, _validate_mermaid
from src.agent import run_agent, stream_agent

INSECURE_MANIFEST = (Path(__file__).parent.parent / "data/manifests/insecure-pod.yaml").read_text()
SECURE_MANIFEST = (Path(__file__).parent.parent / "data/manifests/secure-deployment.yaml").read_text()


@pytest.fixture(scope="module")
def diagram_output():
    return generate_diagram.invoke("Kubernetes RBAC")


@pytest.fixture(scope="module")
def checklist_output():
    return generate_checklist.invoke("Pod Security Admission")


@pytest.fixture(scope="module")
def threat_model_output():
    return generate_threat_model.invoke("etcd access")


class TestGenerateDiagram:
    def test_starts_with_graph_td(self, diagram_output):
        assert "graph TD" in diagram_output

    def test_no_sequence_syntax(self, diagram_output):
        """LLM must not mix in sequenceDiagram syntax inside graph TD."""
        assert "participant " not in diagram_output
        assert "->>" not in diagram_output

    def test_has_nodes_and_edges(self, diagram_output):
        assert "-->" in diagram_output

    def test_not_empty(self, diagram_output):
        assert len(diagram_output.strip()) > 50


class TestGenerateChecklist:
    def test_is_markdown_table(self, checklist_output):
        assert "|" in checklist_output

    def test_has_required_columns(self, checklist_output):
        header = checklist_output.split("\n")[0].lower()
        assert "control" in header
        assert "description" in header
        assert "priority" in header
        assert "source" in header

    def test_has_source_footer(self, checklist_output):
        assert "LFS260" in checklist_output
        assert "pp." in checklist_output

    def test_has_multiple_rows(self, checklist_output):
        rows = [l for l in checklist_output.split("\n") if l.startswith("|") and "---" not in l]
        assert len(rows) >= 4  # header + at least 3 data rows


class TestGenerateThreatModel:
    def test_starts_with_sequence_diagram(self, threat_model_output):
        assert "sequenceDiagram" in threat_model_output

    def test_no_graph_td_syntax(self, threat_model_output):
        assert "graph TD" not in threat_model_output

    def test_has_participants(self, threat_model_output):
        assert "participant" in threat_model_output

    def test_no_runaway_repetition(self, threat_model_output):
        """Detect padding: no single line should repeat more than 3 times."""
        lines = [l.strip() for l in threat_model_output.split("\n") if l.strip()]
        from collections import Counter
        counts = Counter(lines)
        repeated = {l: c for l, c in counts.items() if c > 3}
        assert not repeated, f"Repeated lines detected: {repeated}"


class TestRunAgent:
    def test_diagram_query_returns_mermaid(self):
        result = run_agent("Generate a Mermaid architecture diagram for network policies")
        assert "graph TD" in result

    def test_threat_model_query_returns_sequence(self):
        result = run_agent("Generate a threat model for Pod Security Admission")
        assert "sequenceDiagram" in result

    def test_no_prose_wrapper(self):
        """Agent must not wrap output with 'Here is a diagram...' prose."""
        result = run_agent("Generate a Mermaid architecture diagram for RBAC")
        first_line = result.strip().split("\n")[0]
        assert not first_line.lower().startswith("here")
        assert not first_line.lower().startswith("below")


class TestStreamAgent:
    def test_returns_correct_content(self, capsys):
        result = stream_agent("Generate a Mermaid architecture diagram for RBAC")
        assert "graph TD" in result

    def test_streams_to_stdout(self, capsys):
        """Tokens must be printed incrementally, not held until return."""
        stream_agent("Generate a Mermaid architecture diagram for audit logging")
        captured = capsys.readouterr()
        assert "graph TD" in captured.out

    def test_return_value_matches_stdout(self, capsys):
        """The returned string and what was printed to stdout must be the same content."""
        result = stream_agent("Generate a hardening checklist for etcd")
        captured = capsys.readouterr()
        # stdout has a trailing newline added by stream_agent; strip both for comparison
        assert result.strip() == captured.out.strip()


class TestSessionMemory:
    def test_different_thread_ids_are_independent(self):
        """Two threads must not share message history."""
        import uuid
        t1, t2 = str(uuid.uuid4()), str(uuid.uuid4())
        run_agent("Generate a diagram for RBAC", thread_id=t1)
        # Fresh thread — agent has no knowledge of t1's conversation
        result = run_agent(
            "Summarise our conversation so far in one sentence. "
            "If we have not spoken before, reply only: 'No prior conversation.'",
            thread_id=t2,
        )
        assert "RBAC" not in result

    def test_same_thread_retains_context(self):
        """Second turn in the same thread must recall the first turn's topic."""
        import uuid
        tid = str(uuid.uuid4())
        run_agent("Generate a checklist for Pod Security Admission", thread_id=tid)
        result = run_agent(
            "Without calling any tools, tell me: what Kubernetes topic did I ask about "
            "in my previous message? Reply in one sentence.",
            thread_id=tid,
        )
        assert any(kw in result.lower() for kw in ["pod security", "admission", "psa"])


class TestExtractSecuritySummary:
    """Unit tests for the YAML parser — no Ollama required."""

    def test_detects_privileged_container(self):
        parsed = _extract_security_summary(INSECURE_MANIFEST)
        assert any("privileged" in r for r in parsed["risks"])

    def test_detects_host_pid(self):
        parsed = _extract_security_summary(INSECURE_MANIFEST)
        assert any("hostPID" in r for r in parsed["risks"])

    def test_detects_host_network(self):
        parsed = _extract_security_summary(INSECURE_MANIFEST)
        assert any("hostNetwork" in r for r in parsed["risks"])

    def test_detects_default_service_account(self):
        parsed = _extract_security_summary(INSECURE_MANIFEST)
        assert any("default SA" in r for r in parsed["risks"])

    def test_detects_host_path_volume(self):
        parsed = _extract_security_summary(INSECURE_MANIFEST)
        assert any("hostPath" in r for r in parsed["risks"])

    def test_detects_latest_image_tag(self):
        parsed = _extract_security_summary(INSECURE_MANIFEST)
        assert any("latest" in r for r in parsed["risks"])

    def test_recognises_secure_controls(self):
        parsed = _extract_security_summary(SECURE_MANIFEST)
        controls = " ".join(parsed["controls"])
        assert "runAsNonRoot" in controls
        assert "allowPrivilegeEscalation: false" in controls
        assert "drop ALL" in controls

    def test_invalid_yaml_does_not_raise(self):
        parsed = _extract_security_summary("not: valid: yaml: [[[")
        assert parsed["kind"] == "Unknown"


class TestMermaidValidator:
    def test_valid_graph_td(self):
        ok, _ = _validate_mermaid("graph TD\n    A[Foo] --> B[Bar]")
        assert ok

    def test_valid_sequence_diagram(self):
        ok, _ = _validate_mermaid("sequenceDiagram\n    A->>B: attack")
        assert ok

    def test_rejects_missing_keyword(self):
        ok, reason = _validate_mermaid("Here is your diagram:\ngraph TD\n    A --> B")
        assert not ok
        assert "does not start" in reason

    def test_rejects_graph_with_no_edges(self):
        ok, reason = _validate_mermaid("graph TD\n    A[Foo]")
        assert not ok
        assert "no edges" in reason

    def test_rejects_sequence_with_no_messages(self):
        ok, reason = _validate_mermaid("sequenceDiagram\n    participant A")
        assert not ok
        assert "no messages" in reason

    def test_rejects_unmatched_brackets(self):
        ok, reason = _validate_mermaid("graph TD\n    A[Foo [bar]] --> B[Baz]")
        assert not ok
        assert "unmatched brackets" in reason

    def test_clean_strips_fences(self):
        fenced = "```mermaid\ngraph TD\n    A --> B\n```"
        assert _clean_mermaid(fenced) == "graph TD\n    A --> B"

    def test_clean_passthrough_for_bare_mermaid(self):
        bare = "graph TD\n    A --> B"
        assert _clean_mermaid(bare) == bare


class TestAnalyzeManifest:
    def test_returns_mermaid_diagram(self):
        result = analyze_manifest.invoke(INSECURE_MANIFEST)
        assert "graph TD" in result

    def test_diagram_mentions_risk(self):
        result = analyze_manifest.invoke(INSECURE_MANIFEST)
        assert "RISK" in result.upper() or "privileged" in result.lower()

    def test_secure_manifest_shows_controls(self):
        result = analyze_manifest.invoke(SECURE_MANIFEST)
        assert "graph TD" in result
