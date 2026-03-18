# src/chain.py
from dotenv import load_dotenv
load_dotenv()

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

# 1. Prompt template — your input shape
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a CKS exam assistant. Answer based only on the provided context."),
    ("human", "Context: {context}\n\nQuestion: {question}")
])

# 2. LLM — your model
llm = ChatOllama(model="llama3.2")


# 3. Output parser — clean the response
output_parser = StrOutputParser()

# 4. Basic chain — pipe them together LCEL style (manual context)
chain = prompt | llm | output_parser


# 5. RAG chain — retriever pulls context automatically from vectorstore
def format_docs(docs):
    return "\n\n".join(doc.page_content for doc in docs)


def get_rag_chain():
    from src.vectorstore import get_retriever
    retriever = get_retriever()
    return (
        {"context": retriever | format_docs, "question": RunnablePassthrough()}
        | prompt
        | llm
        | output_parser
    )
