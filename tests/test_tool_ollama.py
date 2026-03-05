# update test_setup.py — zero API key needed
from langchain_ollama import ChatOllama

llm = ChatOllama(model="llama3.2")
response = llm.invoke("Say 'CKS RAG Agent is alive' and nothing else")
print(response.content)