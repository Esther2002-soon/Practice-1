import os
from dotenv import load_dotenv
from  pathlib import Path

class Config:

    DB_URL = os.environ.get(
        "DB_URL", "postgresql://postgres:postgresmaster@localhost:5432/test"
    )

    ACCESS_TOKEN_EXPIRE_MINUTES = int(
        os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 30)
    )

    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "27dca95380ad178fd2380d8f982c96d7cb0c9e5d187caca3ab016f9ecbcdac84",
    )

    HASH_ALGORITHM = os.environ.get("HASH_ALGORITHM", "HS256")
