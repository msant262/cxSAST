from app.database import Base, engine
from app.models import User, Scan, Vulnerability
from app.auth import create_default_user
from app.database import SessionLocal

# Drop all tables
Base.metadata.drop_all(bind=engine)

# Create all tables
Base.metadata.create_all(bind=engine)

# Create default user
db = SessionLocal()
try:
    create_default_user(db)
    print("Database recreated successfully!")
finally:
    db.close() 