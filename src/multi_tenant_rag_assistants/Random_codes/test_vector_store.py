from openai import OpenAI
from langchain_openai.embeddings import OpenAIEmbeddings
import chromadb
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
import tempfile
import shutil
import os
from dotenv import load_dotenv

load_dotenv()

embeddings_model = OpenAIEmbeddings(model="text-embedding-3-small")

SAMPLE_DOCS = [
    Document(
        page_content="LangChain is a framework for developing applications powered by language models.",
        metadata={"source": "langchain_docs", "topic": "overview"},
    ),
    Document(
        page_content="LangGraph is a library for building stateful, multi-actor applications with LLMs.",
        metadata={"source": "langgraph_docs", "topic": "overview"},
    ),
    Document(
        page_content="Vector stores are databases optimized for storing and searching embeddings.",
        metadata={"source": "vector_guide", "topic": "database"},
    ),
    Document(
        page_content="RAG combines retrieval with generation for more accurate LLM responses.",
        metadata={"source": "rag_guide", "topic": "architecture"},
    ),
    Document(
        page_content="Embeddings convert text into numerical vectors for semantic similarity.",
        metadata={"source": "embeddings_guide", "topic": "fundamentals"},
    ),
    Document(
        page_content="Chroma is an open-source embedding database for AI applications.",
        metadata={"source": "chroma_docs", "topic": "database"},
    ),
    Document(
        page_content="FAISS is a library for efficient similarity search developed by Facebook.",
        metadata={"source": "faiss_docs", "topic": "database"},
    ),
    Document(
        page_content="Pinecone is a managed vector database service for production workloads.",
        metadata={"source": "pinecone_docs", "topic": "database"},
    ),
]



def test_chromadb() -> None:
    print("================")
    chroma_client = chromadb.Client()

    collection_name = "test_collection"
    collection = chroma_client.get_or_create_collection(name=collection_name)

    documents = [
        {"id": "doc_1", "text": "Hello world"},
        {"id": "doc_2", "text": "This is a test document."},
        {"id": "doc_3", "text": "ChromaDB is a vector database."}
    ]

    query_text = "Hello world"

    for doc in documents:
        collection.upsert(ids=doc["id"], documents=[doc["text"]])

    result = collection.query(query_texts=[query_text], n_results=3)

    print(result)

    print("initializing completed")
    

def chroma_basics() -> None:
    print("================")
    tmpdir = "docs\\langchain_chroma"
    # create vector store from documents
    vectorstore = Chroma.from_documents(
        documents=SAMPLE_DOCS, embedding=embeddings_model, persist_directory=tmpdir)
    print(f"Vector store created {vectorstore._collection.count()} documents and persisted.")
    # perform similarity search
    query = "What is LangChain?"
    results = vectorstore.similarity_search(query, k=2)
    print(f"Top 2 results for query '{query}':")
    for i, doc in enumerate(results):
        print(
            f"Result {i+1}: {doc.page_content} (Source: {doc.metadata['source']})")

def similarity_search_with_scores():
    tmpdir = "docs\\langchain_chroma"
    # create vector store from documents
    vectorstore = Chroma.from_documents(documents=SAMPLE_DOCS, embedding=embeddings_model, persist_directory=tmpdir)
    # perform similarity search with scores
    query = "Explain vector stores."
    results_with_scores = vectorstore.similarity_search_with_score(query, k=3)
    print(f"Top 3 results with scores for query '{query}':")
    for i, (doc, score) in enumerate(results_with_scores):
        similarity = 1 / (1 + score)  # Convert distance to similarity
        print(
            f"Result {i+1}: {doc.page_content}, (score: {score:.4f}, similarity: {similarity:.4f}, Source: {doc.metadata['source']})")


def metadata_filtering():
    tmpdir = "docs\\langchain_chroma"
    # create vector store from documents
    vectorstore = Chroma.from_documents(documents=SAMPLE_DOCS, embedding=embeddings_model, persist_directory=tmpdir)
    query = "What databases are available?"
    # without metadata filtering
    results = vectorstore.similarity_search(query, k=5)
    print(f"Results without metadata filtering for query '{query}':")
    for i, doc in enumerate(results):
        print(f"Result {i+1}: {doc.page_content} (Source: {doc.metadata['source']})")
    # with metadata filtering
    filter_criteria = {"topic": "database"}
    filtered_results = vectorstore.similarity_search(query, k=5, filter=filter_criteria)
    print(f"\nResults with metadata filtering for query '{query}':")
    for i, doc in enumerate(filtered_results):
        print(f"Result {i+1}: {doc.page_content} (Source: {doc.metadata['source']})")


def main() -> None:
    #test_chromadb()
    #chroma_basics()
    #similarity_search_with_scores()
    metadata_filtering()

if __name__ == "__main__":
    main()