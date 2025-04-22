from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from ..database import get_db
from ..models import Scan, Vulnerability, User
from ..auth import get_current_user
from ..services.semgrep_service import SemgrepService
from ..services.file_service import FileService
import os
from datetime import datetime

router = APIRouter()

@router.post("/scan")
async def create_scan(
    file: UploadFile = File(...),
    project_name: str = Form(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Criar registro do scan
        scan = Scan(
            project_name=project_name,
            user_id=current_user.id,
            start_time=datetime.utcnow(),
            status="pending"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Salvar arquivo
        file_service = FileService()
        file_path = file_service.save_uploaded_file(file, scan.id)
        if not file_path:
            raise HTTPException(status_code=422, detail="Failed to save uploaded file")

        # Extrair ZIP
        extract_dir = os.path.dirname(file_path)
        if not file_service.extract_zip(file_path, extract_dir):
            raise HTTPException(status_code=422, detail="Failed to extract ZIP file")

        # Iniciar análise em background
        background_tasks.add_task(analyze_scan, scan.id, extract_dir, db)

        return {"id": scan.id, "status": "pending"}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=422, detail=str(e))

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

async def analyze_scan(scan_id: int, directory: str, db: Session):
    try:
        # Atualizar status para analyzing
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = "analyzing"
        db.commit()

        # Inicializar serviços
        semgrep_service = SemgrepService()
        file_service = FileService()

        # Analisar diretório
        vulnerabilities = semgrep_service.analyze_directory(directory)
        
        # Salvar vulnerabilidades
        total_files = 0
        total_loc = 0
        total_issues = len(vulnerabilities)

        for vuln in vulnerabilities:
            db_vuln = Vulnerability(
                scan_id=scan_id,
                file_path=vuln["metadata"]["path"],
                line_number=vuln["line_number"],
                rule_id=vuln["rule_id"],
                severity=vuln["severity"],
                message=vuln["message"],
                vulnerability_metadata=vuln["metadata"]
            )
            db.add(db_vuln)

        # Atualizar scan
        scan.status = "completed"
        scan.total_files = total_files
        scan.total_loc = total_loc
        scan.total_issues = total_issues
        scan.end_time = datetime.utcnow()
        db.commit()

    except Exception as e:
        # Atualizar scan com erro
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = "failed"
        scan.error_message = str(e)
        scan.end_time = datetime.utcnow()
        db.commit()

        # Limpar arquivos
        file_service.cleanup_scan_files(scan_id) 