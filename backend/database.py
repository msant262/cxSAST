from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, create_engine, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import os
import uuid

# Get the absolute path to the data directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Configuração do banco de dados SQLite
DB_PATH = os.path.join(DATA_DIR, "scans.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

print(f"Database path: {DB_PATH}")

# Remove existing database file if it exists
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)
    print(f"Removed existing database file: {DB_PATH}")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=True  # Adiciona logging para debug
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True)
    project_name = Column(String)
    status = Column(String)
    start_time = Column(DateTime)
    end_time = Column(DateTime, nullable=True)
    progress = Column(Integer)
    current_file = Column(String, nullable=True)
    total_files = Column(Integer)
    total_issues = Column(Integer)
    total_loc = Column(Integer)
    error = Column(String, nullable=True)

    vulnerabilities = relationship("Vulnerability", back_populates="scan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"))
    file = Column(String)
    line = Column(Integer)
    rule = Column(String)
    message = Column(String)
    severity = Column(String)
    is_ignored = Column(Integer, default=0)
    is_false_positive = Column(Integer, default=0)
    cwe_id = Column(String, nullable=True)
    cwe_name = Column(String, nullable=True)
    cwe_description = Column(Text, nullable=True)
    cve_id = Column(String, nullable=True)
    cve_description = Column(Text, nullable=True)
    cve_cvss_score = Column(Float, nullable=True)
    source_code = Column(Text, nullable=True)
    highlighted_line = Column(Integer, nullable=True)
    remediation = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")

# Create tables
try:
    Base.metadata.create_all(bind=engine)
    print(f"Database tables created at: {DB_PATH}")
except Exception as e:
    print(f"Error creating database tables: {str(e)}")
    raise

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 