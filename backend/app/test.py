from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

print("Testing SQLAlchemy in app directory...")

# Create engine
engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})

# Create session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Test session
session = SessionLocal()
print("SQLAlchemy is working correctly in app directory!")
session.close() 