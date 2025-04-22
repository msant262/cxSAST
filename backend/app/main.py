import os
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from .database import get_db, Base, engine, Scan, Vulnerability
from sqlalchemy.sql import func, desc
from datetime import datetime, timedelta
from fastapi import HTTPException
import logging
import shutil
import uuid
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the absolute path to the data directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Create database tables
Base.metadata.create_all(bind=engine)

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

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/test-db")
async def test_db(db: Session = Depends(get_db)):
    return {"message": "Database connection successful"}

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db)):
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
            Vulnerability.rule,
            Vulnerability.severity,
            func.count(Vulnerability.id).label('count')
        ).group_by(Vulnerability.rule, Vulnerability.severity)\
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
                    "date": date_str,
                    "count": count.count or 0
                })

        # Scan status counts
        scan_status_counts = dict(db.query(
            Scan.status,
            func.count(Scan.id)
        ).group_by(Scan.status).all()) or {}

        # Average scan duration
        completed_scans = db.query(Scan).filter(Scan.status == 'COMPLETED').all()
        total_duration = sum(
            (scan.end_time - scan.start_time).total_seconds()
            for scan in completed_scans
            if scan.end_time and scan.start_time
        )
        average_duration = total_duration / len(completed_scans) if completed_scans else 0
        average_duration_str = str(timedelta(seconds=int(average_duration)))

        return {
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerability_counts": vulnerability_counts,
            "recent_scans": [
                {
                    "id": scan.id,
                    "project_name": scan.project_name,
                    "start_time": scan.start_time.strftime("%Y-%m-%dT%H:%M:%S") if scan.start_time else None,
                    "status": scan.status,
                    "vulnerability_count": scan.vulnerability_count or 0
                }
                for scan in recent_scans
            ],
            "top_projects": [
                {
                    "name": proj.project_name,
                    "scan_count": 0,  # TODO: Add scan count
                    "vulnerability_count": proj.vulnerability_count or 0
                }
                for proj in top_projects
            ],
            "daily_scan_counts": formatted_daily_counts,
            "scan_status_counts": scan_status_counts,
            "average_duration": average_duration_str,
            "top_vulnerabilities": [
                {
                    "rule": vuln.rule,
                    "severity": vuln.severity,
                    "count": vuln.count or 0
                }
                for vuln in top_vulnerabilities
            ]
        }
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan")
async def create_scan(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db)
):
    try:
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        scan_dir = os.path.join(DATA_DIR, scan_id)
        
        # Remove directory if it exists
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)
        
        # Create new directory
        os.makedirs(scan_dir)
        logger.info(f"Created scan directory: {scan_dir}")
        
        # Save uploaded file
        file_path = os.path.join(scan_dir, file.filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Verify file was saved
        if not os.path.exists(file_path):
            raise HTTPException(status_code=500, detail="Failed to save uploaded file")
        
        logger.info(f"Saved uploaded file: {file_path}")
        
        # Extract if ZIP
        if file.filename.endswith('.zip'):
            extracted_dir = os.path.join(scan_dir, "extracted")
            os.makedirs(extracted_dir)
            shutil.unpack_archive(file_path, extracted_dir)
            logger.info(f"Extracted ZIP to: {extracted_dir}")
        
        # Create scan record
        scan = Scan(
            id=scan_id,
            project_name=file.filename,
            status="PENDING",
            start_time=datetime.now(),
            progress=0,
            total_files=0,
            total_issues=0,
            total_loc=0
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Start background task
        background_tasks.add_task(process_scan, scan_id, db)
        
        return {"scanId": scan_id}
        
    except Exception as e:
        logger.error(f"Error creating scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

async def process_scan(scan_id: str, db: Session):
    """Process the scan in the background."""
    try:
        # Get the scan from the database
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        # Update scan status
        scan.status = "RUNNING"
        db.commit()

        # Get the scan directory
        scan_dir = os.path.join(DATA_DIR, scan_id)
        extracted_dir = os.path.join(scan_dir, "extracted")

        # Count total files
        total_files = 0
        for root, _, files in os.walk(extracted_dir):
            for file in files:
                if file.endswith(('.cpp', '.h', '.hpp', '.c', '.py', '.js', '.ts')):
                    total_files += 1

        scan.total_files = total_files
        db.commit()

        # Process each file
        processed_files = 0
        for root, _, files in os.walk(extracted_dir):
            for file in files:
                if file.endswith(('.cpp', '.h', '.hpp', '.c', '.py', '.js', '.ts')):
                    try:
                        file_path = os.path.join(root, file)
                        scan.current_file = os.path.relpath(file_path, extracted_dir)
                        scan.progress = int((processed_files + 1) / total_files * 100)
                        db.commit()

                        # TODO: Implement actual file analysis here
                        await asyncio.sleep(1)  # Simulate processing time

                        processed_files += 1
                        logger.info(f"Processed file {processed_files}/{total_files}: {file}")

                    except Exception as e:
                        logger.error(f"Error processing file {file}: {str(e)}")
                        continue

        # Update scan status
        scan.status = "COMPLETED"
        scan.end_time = datetime.now()
        scan.progress = 100
        db.commit()

        logger.info(f"Scan completed: {scan_id}")

    except Exception as e:
        logger.error(f"Error processing scan {scan_id}: {str(e)}")
        try:
            scan.status = "ERROR"
            scan.error = str(e)
            db.commit()
        except:
            logger.error("Failed to update scan status to ERROR") 