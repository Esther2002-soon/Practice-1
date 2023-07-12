from sqlalchemy import create_engine, Column, Integer, String, Date, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from datetime import datetime
from models.usertable import User
from config import Config

engine = create_engine(Config.DB_URL)
Session = sessionmaker(bind=engine)
session = Session()

mycrypt = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
def create_password_digest(password):
    return mycrypt.hash(password)
    
user1 = User(username = 'Alice', password=create_password_digest('password1'), birthday=datetime(2002, 10, 19))
user2 = User(username = 'Bob', password=create_password_digest('password2'), birthday=datetime(2003, 4, 24))
user3 = User(username = 'Charles', password=create_password_digest('password3'), birthday=datetime(2002, 7, 1))

query = session.query(User).filter(User.username=="b").first()
session.delete(query)
#users = [user7]
#session.add_all(users)
session.commit()
session.close()
