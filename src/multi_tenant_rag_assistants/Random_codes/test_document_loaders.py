import os
import tempfile
from pathlib import Path
from langchain_community.document_loaders import (
    TextLoader,
    WebBaseLoader,
    DirectoryLoader,
    PyPDFLoader
)

from dotenv import load_dotenv
load_dotenv()

def load_text_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_file:
        temp_file.write(b"Hello, this is a sample text file\nThis file is used for testing.\n")
        temp_file_path = temp_file.name

    try:
        loader = TextLoader(temp_file_path)
        documents = loader.load()

        for doc in documents:
            print(f"===Document Object===\n")
            print(doc)
            print(f"===Document Content===\n")
            print(doc.page_content)

    finally:
        os.remove(temp_file_path)

def pdf_loader(pdf_path: str):
    loader = PyPDFLoader(pdf_path)
    documents = loader.load()

    print(f"Loaded {len(documents)} document(s) from PDF")
    for i, doc in enumerate(documents):
        print(f"===Document {i + 1} Content Preview {doc.page_content[:100]}===")
        print(f"===Metadata {doc.metadata}===\n")

def main() -> None:
    print("===Setup complete!===")
    #load_text_file()
    pdf_loader("docs\\langchain_demo.pdf")

if __name__ == "__main__":
    main()