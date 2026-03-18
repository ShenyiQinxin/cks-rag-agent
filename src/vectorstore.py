from langchain_community.vectorstores import FAISS
from src.embeddings import get_embeddings

INDEX_PATH = "faiss_index"


def build_vectorstore(chunks: list):
    embeddings = get_embeddings()
    vectorstore = FAISS.from_documents(chunks, embeddings)
    vectorstore.save_local(INDEX_PATH)
    return vectorstore


def load_vectorstore():
    embeddings = get_embeddings()
    return FAISS.load_local(INDEX_PATH, embeddings, allow_dangerous_deserialization=True)


def get_retriever(k: int = 4):
    vectorstore = load_vectorstore()
    return vectorstore.as_retriever(search_kwargs={"k": k})
