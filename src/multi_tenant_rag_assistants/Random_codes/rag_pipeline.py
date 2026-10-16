from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.runnables import RunnablePassthrough, RunnableParallel
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain.chat_models import init_chat_model
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pydantic import BaseModel, Field
from typing import List
import tempfile
from dotenv import load_dotenv

load_dotenv()
embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")

# Sample knowledge base
KNOWLEDGE_BASE = """# LangChain Framework

LangChain is a framework for developing applications powered by language models. It was created by Harrison Chase in October 2022.

## Core Components

1. **Models**: LangChain supports various LLM providers including OpenAI, Anthropic, and local models.

2. **Prompts**: Templates for structuring inputs to language models.

3. **Chains**: Sequences of calls to models and other components.

4. **Agents**: Systems that use LLMs to determine which actions to take.

5. **Memory**: Components for persisting state between chain/agent calls.

## LangGraph

LangGraph is a library for building stateful, multi-actor applications. Key features:
- State management
- Cycles and loops
- Human-in-the-loop
- Persistence

## Pricing

LangChain itself is open source and free. LangSmith (the observability platform) has a free tier and paid plans starting at $39/month.

## Getting Started

Install with: pip install langchain langchain-openai
Create your first chain in under 10 lines of code.
"""


def create_knowledge_base():
    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    doc = Document(page_content=KNOWLEDGE_BASE,
                   metadata={"source":"langchain_knowledge_base"})

    chunks = splitter.split_documents([doc])

    vector_store = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings_model,
        persist_directory=tempfile.mkdtemp())

    return vector_store

def demo_basic_rag():
    vector_store = create_knowledge_base()

    retriever = vector_store.as_retriever(search_type = "similarity",
                                           search_kwargs={"k": 2})
    llm = init_chat_model(model="gpt-4o-mini", 
                          temperature=0.2) 

    prompt = ChatPromptTemplate.from_template(
        """
Answer the question based on the context below. Include which sources you used.

Context:
{context}

Question: {question}

Answer (include sources):
Make sure to answer in a concise and clear manner,and if you don't know the answer, say "I don't know"."""
    )

    def format_docs(docs):
        return "\n\n".join([doc.page_content for doc in docs])

    rag_chain =(
                {"context": retriever | format_docs, "question": RunnablePassthrough()}
                | prompt
                | llm
                | StrOutputParser())

    questions = ["What is LangChain?",
                "What are the core components of LangChain?",
                "What is LangGraph?",
                "How can I get started with LangChain?"]

    print("========Basic RAG Demo========")
    for q in questions:
        answer = rag_chain.invoke(q)
        print(f"Question: {q}")
        print(f"Answer: {answer}")
        print("-" * 50)


def main():
    print("======Running RAG pipeline...======")
    demo_basic_rag()

if __name__ == "__main__":
    main()