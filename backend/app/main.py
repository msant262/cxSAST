import os
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks, Form, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import get_db, Base, engine, SessionLocal
from .models import Scan, Vulnerability, User
from sqlalchemy.sql import func, desc
from datetime import datetime, timedelta
from fastapi import HTTPException
import logging
import shutil
import uuid
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from .analyzer.semgrep_analyzer import SemgrepAnalyzer, Vulnerability as SemgrepVulnerability
from .analyzer.core import VulnerabilityAnalyzer
from .auth import get_current_user, create_default_user
from .routers import auth, scan
from . import models, schemas, security
from .config import create_directories

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the absolute path to the data directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Create database tables
Base.metadata.create_all(bind=engine)

# Criar diretórios necessários
create_directories()

# Define DashboardStats model
class DashboardStats(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    vulnerability_counts: Dict[str, int]
    recent_scans: List[Dict]
    top_projects: List[Dict]
    daily_scan_counts: List[Dict]
    scan_status_counts: Dict[str, int]
    average_duration: str
    top_vulnerabilities: List[Dict]

app = FastAPI(title="cxSAST API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security configuration
SECRET_KEY = "your-secret-key"  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# User authentication
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Create default admin user
@app.on_event("startup")
def create_admin_user():
    db = SessionLocal()
    try:
        create_default_user(db)
    finally:
        db.close()

# Include routers
app.include_router(auth.router, prefix="/api", tags=["auth"])
app.include_router(scan.router, prefix="/api", tags=["scans"])

@app.get("/")
def read_root():
    return {"message": "Welcome to cxSAST API"}

@app.get("/test-db")
async def test_db(db: Session = Depends(get_db)):
    return {"message": "Database connection successful"}

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics"""
    try:
        # Total scans and vulnerabilities
        total_scans = db.query(func.count(Scan.id)).scalar() or 0
        total_vulnerabilities = db.query(func.count(Vulnerability.id)).scalar() or 0

        # Vulnerability counts by severity
        vulnerability_counts = dict(db.query(
            Vulnerability.severity,
            func.count(Vulnerability.id)
        ).group_by(Vulnerability.severity).all()) or {}

        # Top vulnerabilities by count
        top_vulnerabilities = db.query(
            Vulnerability.vulnerability_type,
            Vulnerability.severity,
            func.count(Vulnerability.id).label('count')
        ).group_by(Vulnerability.vulnerability_type, Vulnerability.severity)\
         .order_by(desc('count'))\
         .all()

        # Recent scans with vulnerability counts
        recent_scans = db.query(
            Scan.id,
            Scan.project_name,
            Scan.start_time,
            Scan.status,
            func.count(Vulnerability.id).label('vulnerability_count')
        ).outerjoin(Vulnerability, Scan.id == Vulnerability.scan_id)\
         .group_by(Scan.id, Scan.project_name, Scan.start_time, Scan.status)\
         .order_by(Scan.start_time.desc())\
         .limit(10)\
         .all()

        # Top projects by vulnerability count
        top_projects = db.query(
            Scan.project_name,
            func.count(Vulnerability.id).label('vulnerability_count')
        ).outerjoin(Vulnerability, Scan.id == Vulnerability.scan_id)\
         .group_by(Scan.project_name)\
         .order_by(desc('vulnerability_count'))\
         .limit(10)\
         .all()

        # Daily scan counts for the last 30 days
        thirty_days_ago = datetime.now() - timedelta(days=30)
        daily_scan_counts = db.query(
            func.date(Scan.start_time).label('date'),
            func.count(Scan.id).label('count')
        ).filter(Scan.start_time >= thirty_days_ago)\
         .group_by(func.date(Scan.start_time))\
         .order_by(func.date(Scan.start_time))\
         .all()

        # Convert daily_scan_counts to proper format
        formatted_daily_counts = []
        for count in daily_scan_counts:
            if count.date:
                date_str = count.date.strftime("%Y-%m-%d") if isinstance(count.date, datetime) else str(count.date)
                formatted_daily_counts.append({
                    'date': date_str,
                    'count': count.count
                })

        # Calculate scan status counts
        scan_status_counts = dict(db.query(
            Scan.status,
            func.count(Scan.id)
        ).group_by(Scan.status).all())

        # Calculate average duration
        avg_duration = db.query(
            func.avg(Scan.end_time - Scan.start_time)
        ).filter(Scan.end_time.isnot(None)).scalar()

        avg_duration_str = str(avg_duration) if avg_duration else "N/A"

        return DashboardStats(
            total_scans=total_scans,
            total_vulnerabilities=total_vulnerabilities,
            vulnerability_counts=vulnerability_counts,
            recent_scans=[{
                'id': scan.id,
                'project_name': scan.project_name,
                'start_time': scan.start_time.isoformat(),
                'status': scan.status,
                'vulnerability_count': scan.vulnerability_count
            } for scan in recent_scans],
            top_projects=[{
                'project_name': project.project_name,
                'vulnerability_count': project.vulnerability_count
            } for project in top_projects],
            daily_scan_counts=formatted_daily_counts,
            scan_status_counts=scan_status_counts,
            average_duration=avg_duration_str,
            top_vulnerabilities=[{
                'type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'count': vuln.count
            } for vuln in top_vulnerabilities]
        )
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = security.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/users", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = security.get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        created_at=datetime.utcnow(),
        is_active=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/api/scans", response_model=List[schemas.Scan])
def get_scans(
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    return db.query(models.Scan).filter(models.Scan.user_id == current_user.id).all()

@app.get("/api/scans/{scan_id}", response_model=schemas.Scan)
def get_scan(
    scan_id: int,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id,
        models.Scan.user_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/api/scans/{scan_id}/vulnerabilities", response_model=List[schemas.Vulnerability])
def get_scan_vulnerabilities(
    scan_id: int,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id,
        models.Scan.user_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return db.query(models.Vulnerability).filter(models.Vulnerability.scan_id == scan_id).all()

@app.get("/api/scan/{scan_id}/vulnerabilities/{vulnerability_id}")
async def get_vulnerability_details(
    scan_id: str,
    vulnerability_id: str,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id,
        models.Scan.user_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    vulnerability = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id == scan_id,
        models.Vulnerability.id == vulnerability_id
    ).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    return vulnerability

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 