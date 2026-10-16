import os

import psycopg
from dotenv import load_dotenv


load_dotenv()
database_url = os.getenv("DATABASE_URL")
if not database_url:
    raise RuntimeError("DATABASE_URL is not configured in .env")

with psycopg.connect(database_url) as conn:
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hakona (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL
            )
        """)

        # Insert a row safely using query parameters
        cur.execute(
            "INSERT INTO hakona (name, email) VALUES (%s, %s)",
            ("Jinzo2", "jinzo2@example.com"),
        )

        # Read rows
        cur.execute("SELECT id, name, email FROM hakona")
        for user in cur.fetchall():
            print(user)
