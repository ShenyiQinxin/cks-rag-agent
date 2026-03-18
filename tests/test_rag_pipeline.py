"""
Tests for the full RAG pipeline: embed → store → retrieve → chain.
Uses synthetic chunks — no real PDFs required.
"""
import pytest
from langchain_core.documents import Document
from src.embeddings import get_embeddings
from src.vectorstore import build_vectorstore, get_retriever
from src.chain import get_rag_chain

SAMPLE_CHUNKS = [
    Document(page_content="Pod Security Admission has three modes: enforce, audit, and warn. Enforce mode rejects pods that violate the policy."),
    Document(page_content="AppArmor profiles can be applied to containers in Kubernetes using annotations or securityContext fields."),
    Document(page_content="Seccomp profiles restrict system calls a container can make. The RuntimeDefault profile is recommended for CKS."),
    Document(page_content="Network policies in Kubernetes control traffic between pods. By default, all traffic is allowed."),
]


@pytest.fixture(scope="module", autouse=True)
def vectorstore():
    """Build a fresh vectorstore from synthetic chunks before this module's tests."""
    build_vectorstore(SAMPLE_CHUNKS)


def test_retriever_returns_correct_count():
    retriever = get_retriever(k=2)
    results = retriever.invoke("Pod Security Admission modes")
    assert len(results) == 2


def test_retriever_returns_relevant_chunk():
    retriever = get_retriever(k=2)
    results = retriever.invoke("Pod Security Admission modes")
    combined = " ".join(doc.page_content for doc in results)
    assert "Pod Security Admission" in combined


def test_rag_chain_returns_string():
    chain = get_rag_chain()
    result = chain.invoke("What are the Pod Security Admission modes?")
    assert isinstance(result, str)
    assert len(result.strip()) > 10


def test_rag_chain_is_grounded():
    """Response should reference content from the retrieved chunks."""
    chain = get_rag_chain()
    result = chain.invoke("What are the Pod Security Admission modes?")
    # Llama should mention at least one of the three modes from the chunk
    assert any(mode in result.lower() for mode in ["enforce", "audit", "warn"])
