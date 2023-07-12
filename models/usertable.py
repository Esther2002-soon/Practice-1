from sqlalchemy import Column, Integer, String, Date, UnicodeText,VARCHAR,DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime,date
from pydantic import BaseModel
from typing import List

Base = declarative_base()

class User(Base):
     __tablename__ = 'usertable'

     username = Column(VARCHAR , primary_key = True)
     password = Column(VARCHAR, nullable = False)
     birthday = Column(Date)
     create_time = Column(DateTime,default=datetime.utcnow())
     last_login = Column(DateTime, nullable = True)
