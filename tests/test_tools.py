# test_setup.py — run this to confirm
from pathlib import Path

from langchain_anthropic import ChatAnthropic
from dotenv import load_dotenv
import os

from langchain_openai import ChatOpenAI

load_dotenv(Path(__file__).parent.parent / ".env")

print("Key loaded:", bool(os.getenv("OPENAI_API_KEY")))

DEV_MODEL = "claude-haiku-4-5-20251001"    # cheap, fast, dev testing
PROD_MODEL = "claude-sonnet-4-6"           # better quality, production
llm = ChatOpenAI(model="gpt-4o-mini")
response = llm.invoke("Say 'CKS RAG Agent is alive' and nothing else")
print(response.content)