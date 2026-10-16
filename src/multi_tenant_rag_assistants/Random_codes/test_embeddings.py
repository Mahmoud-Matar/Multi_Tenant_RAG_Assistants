from langchain_openai import ChatOpenAI
import os
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv()


def main() -> None:

    print("====================")

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    conversation = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of Egypt?"}
        ]
    )

    print(conversation.choices[0].message.content)

    print("====================\n")

    embedding = client.embeddings.create(
        model="text-embedding-3-small",
        input="Hello world")

    print(embedding)

    print("====================")


if __name__ == "__main__":
    main()