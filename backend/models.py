from sqlalchemy import Integer, String, Column, ForeignKey
from database import engine, Base

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    hashed_passowrd = Column(String)
    
User.metadata.create_all(bind=engine)