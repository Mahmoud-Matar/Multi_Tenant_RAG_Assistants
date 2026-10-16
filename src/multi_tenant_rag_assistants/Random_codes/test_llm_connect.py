from dotenv import load_dotenv
load_dotenv()

from importlib.metadata import version
core_version = version("langchain-core")
lg_version = version("langgraph")
from langchain_openai import ChatOpenAI


print(f"LangChain Core Version: {core_version}")
print(f"LangGraph Version: {lg_version}")



def main() -> None:
    print("===Hello from multi-tenant-rag-assistants!===")

    llm = ChatOpenAI(model_name="gpt-4o-mini", temperature=0)
    response = llm.invoke("say 'Hello World, I am Alive!' ")
    print(f"Response from LLM: {response}")

    print("===Setup complete!===")

if __name__ == "__main__":
    main()