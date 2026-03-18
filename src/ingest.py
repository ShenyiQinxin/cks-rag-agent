from pathlib import Path
from langchain_community.document_loaders import PyMuPDFLoader, TextLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter


def load_documents(data_dir: str = "data/raw") -> list:
    docs = []
    data_path = Path(data_dir)

    for file_path in data_path.rglob("*"):
        if file_path.suffix == ".pdf":
            loader = PyMuPDFLoader(str(file_path))
        elif file_path.suffix in (".md", ".txt"):
            loader = TextLoader(str(file_path))
        else:
            continue
        docs.extend(loader.load())

    return docs


def chunk_documents(docs: list, chunk_size: int = 500, chunk_overlap: int = 50) -> list:
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
    )
    return splitter.split_documents(docs)
