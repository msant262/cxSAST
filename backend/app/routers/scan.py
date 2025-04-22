from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from ..database import SessionLocal
from ..models import Scan, Vulnerability, User
from ..auth import get_current_user
from ..analyzer.core import VulnerabilityAnalyzer
from ..analyzer.semgrep_analyzer import SemgrepAnalyzer
import os
import shutil
from datetime import datetime

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/scan")
async def create_scan(
    project_name: str = Form(...),
    files: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Create scan record
        scan = Scan(
            project_name=project_name,
            user_id=current_user.id,
            start_time=datetime.utcnow(),
            status="pending",
            total_files=0,
            total_loc=0,
            total_issues=0
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Create scan directory with absolute path
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        scan_dir = os.path.join(base_dir, "scans", str(scan.id))
        os.makedirs(scan_dir, exist_ok=True)

        # Save uploaded file
        file_path = os.path.join(scan_dir, files.filename)
        try:
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(files.file, buffer)
        except Exception as e:
            # If file saving fails, delete the scan record
            db.delete(scan)
            db.commit()
            raise HTTPException(
                status_code=422,
                detail=f"Failed to save uploaded file: {str(e)}"
            )

        # Start analysis in background
        analyze_scan(scan.id, scan_dir, db)

        return {"id": scan.id, "status": "pending"}
    except Exception as e:
        # Log the error for debugging
        print(f"Error in create_scan: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=422,
            detail=f"Failed to create scan: {str(e)}"
        )

@router.get("/scans")
def get_scans(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).offset(skip).limit(limit).all()
    return scans

@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/scans/{scan_id}/vulnerabilities")
def get_scan_vulnerabilities(
    scan_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).offset(skip).limit(limit).all()
    return vulnerabilities

def analyze_scan(scan_id: int, scan_dir: str, db: Session):
    analyzer = VulnerabilityAnalyzer()
    semgrep_analyzer = SemgrepAnalyzer()
    total_files = 0
    total_loc = 0
    total_issues = 0

    for root, _, files in os.walk(scan_dir):
        for file in files:
            if file.endswith(('.py', '.js', '.java', '.cpp', '.c', '.php')):
                file_path = os.path.join(root, file)
                total_files += 1
                
                with open(file_path, 'r') as f:
                    content = f.read()
                    total_loc += len(content.splitlines())
                
                # Run both analyzers
                core_vulnerabilities = analyzer.analyze_file(file_path)
                semgrep_vulnerabilities = semgrep_analyzer.analyze_file(file_path)
                
                # Combine results
                vulnerabilities = core_vulnerabilities + semgrep_vulnerabilities
                total_issues += len(vulnerabilities)
                
                for vuln in vulnerabilities:
                    db_vuln = Vulnerability(
                        scan_id=scan_id,
                        file_path=file_path,
                        line_number=vuln['line_number'],
                        vulnerability_type=vuln['type'],
                        severity=vuln['severity'],
                        description=vuln['description'],
                        remediation=vuln['remediation'],
                        rule=vuln.get('rule', '')
                    )
                    db.add(db_vuln)
    
    db.commit()
    
    # Update scan status
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    scan.status = "completed"
    scan.total_files = total_files
    scan.total_loc = total_loc
    scan.total_issues = total_issues
    scan.end_time = datetime.utcnow()
    db.commit() 