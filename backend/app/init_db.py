from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, User
from .main import get_password_hash

SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Create default user if it doesn't exist
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        if not user:
            user = User(
                username="admin",
                email="admin@example.com",
                hashed_password=get_password_hash("admin")
            )
            db.add(user)
            db.commit()
            print("Default user created successfully")
        else:
            print("Default user already exists")
    finally:
        db.close()

if __name__ == "__main__":
    init_db() 