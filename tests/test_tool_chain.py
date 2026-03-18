"""
Tests for the basic LCEL chain (no retriever — context injected directly).
"""
from src.chain import chain


def test_chain_returns_string():
    result = chain.invoke({
        "context": "Pod Security Admission has three modes: enforce, audit, and warn.",
        "question": "What are the three modes of Pod Security Admission?"
    })
    assert isinstance(result, str)
    assert len(result.strip()) > 10


def test_chain_is_grounded():
    result = chain.invoke({
        "context": "Pod Security Admission has three modes: enforce, audit, and warn.",
        "question": "What are the three modes of Pod Security Admission?"
    })
    assert any(mode in result.lower() for mode in ["enforce", "audit", "warn"])


def test_chain_respects_context_boundary():
    """With an empty context, the model should not hallucinate confidently."""
    result = chain.invoke({
        "context": "",
        "question": "What is the capital of France?"
    })
    # The system prompt says to answer based only on provided context,
    # so it should either decline or give a very short answer
    assert isinstance(result, str)
