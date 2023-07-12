from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from fastapi import Depends
from config import Config


def get_db() -> Session:
    engine = create_engine(Config.DB_URL)
    db = Session(bind=engine)
    try:
        yield db
    finally:
        db.close()