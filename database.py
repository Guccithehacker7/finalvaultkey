import sqlite3

def init_db():
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            public_key TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_user(username, public_key_pem):
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO users (username, public_key) VALUES (?, ?)",
        (username, public_key_pem)
    )

    conn.commit()
    conn.close()