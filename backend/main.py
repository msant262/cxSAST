import os
import sys
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import shutil
import uuid
from datetime import datetime, timedelta
import logging
from app.database import SessionLocal, Scan, Vulnerability, engine, Base, get_db
import uvicorn
import zipfile
import asyncio
import random
from typing import List, Dict, Any, Optional
import json
from pydantic import BaseModel
from sqlalchemy import func, desc
from analyzer.core import VulnerabilityAnalyzer
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

# Create FastAPI app
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Create data directory if it doesn't exist
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)
    print(f"Created data directory: {DATA_DIR}")

SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.join(DATA_DIR, 'scans.db')}"
print(f"Database path: {os.path.join(DATA_DIR, 'scans.db')}")

# Configure SQLite to work with threads
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)

# Create tables
Base.metadata.create_all(bind=engine)

# Create a thread-local session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Global task manager
class TaskManager:
    def __init__(self):
        self.tasks = {}
    
    def add_task(self, scan_id: str, task: asyncio.Task):
        self.tasks[scan_id] = task
    
    def get_task(self, scan_id: str) -> Optional[asyncio.Task]:
        return self.tasks.get(scan_id)
    
    def remove_task(self, scan_id: str):
        if scan_id in self.tasks:
            del self.tasks[scan_id]

# Initialize task manager
task_manager = TaskManager()

# Initialize data directory
data_dir = os.path.join(BASE_DIR, "data")
if not os.path.exists(data_dir):
    os.makedirs(data_dir)
    print(f"Created data directory: {data_dir}")

def count_loc(file_path: str) -> int:
    """Count the number of lines of code in a file, excluding comments and empty lines."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        loc = 0
        in_comment = False
        
        for line in lines:
            # Remove whitespace
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
                
            # Handle multi-line comments
            if '/*' in line:
                in_comment = True
                continue
            if '*/' in line:
                in_comment = False
                continue
            if in_comment:
                continue
                
            # Skip single-line comments
            if line.startswith('//'):
                continue
                
            # Count the line
            loc += 1
            
        return loc
    except Exception as e:
        logger.error(f"Error counting LOC in {file_path}: {str(e)}")
        return 0

# CWE Database (simplified example)
CWE_DATABASE = {
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
        "mitreUrl": "https://cwe.mitre.org/data/definitions/78.html"
    },
    "CWE-79": {
        "name": "Cross-site Scripting (XSS)",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "mitreUrl": "https://cwe.mitre.org/data/definitions/79.html"
    },
    "CWE-89": {
        "name": "SQL Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
        "mitreUrl": "https://cwe.mitre.org/data/definitions/89.html"
    },
    "CWE-119": {
        "name": "Buffer Overflow",
        "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
        "mitreUrl": "https://cwe.mitre.org/data/definitions/119.html"
    },
    "CWE-22": {
        "name": "Path Traversal",
        "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
        "mitreUrl": "https://cwe.mitre.org/data/definitions/22.html"
    }
}

# CVE Database (simplified example)
CVE_DATABASE = {
    "CVE-2021-44228": {
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "cvssScore": 10.0,
        "nvdUrl": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    "CVE-2014-0160": {
        "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, aka the Heartbleed bug.",
        "cvssScore": 7.5,
        "nvdUrl": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    }
}

# Vulnerability rule mappings
RULE_MAPPINGS = {
    "command_injection": {
        "cwe": "CWE-78",
        "cve": None,
        "description": "Command injection vulnerabilities can allow attackers to execute arbitrary commands on the host system.",
        "remediation": {
            "description": "Command injection vulnerabilities occur when untrusted input is used to construct system commands.",
            "steps": [
                "Use parameterized APIs instead of constructing commands with string concatenation",
                "Implement strict input validation",
                "Use a whitelist of allowed commands",
                "Run with minimal privileges"
            ],
            "references": [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html"
            ]
        }
    },
    "sql_injection": {
        "cwe": "CWE-89",
        "cve": None,
        "description": "SQL injection flaws can allow attackers to execute arbitrary SQL commands on the database.",
        "remediation": {
            "description": "SQL injection occurs when untrusted input is used to construct SQL queries.",
            "steps": [
                "Use parameterized queries or prepared statements",
                "Implement proper input validation",
                "Use an ORM framework",
                "Apply the principle of least privilege"
            ],
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html"
            ]
        }
    },
    "xss": {
        "cwe": "CWE-79",
        "cve": None,
        "description": "Cross-site scripting vulnerabilities can allow attackers to execute arbitrary JavaScript in users' browsers.",
        "remediation": {
            "description": "Cross-site scripting occurs when untrusted input is included in web pages without proper encoding.",
            "steps": [
                "Encode all untrusted output",
                "Implement Content Security Policy (CSP)",
                "Use modern frameworks that automatically escape content",
                "Validate and sanitize all user input"
            ],
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html"
            ]
        }
    },
    "buffer_overflow": {
        "cwe": "CWE-119",
        "cve": None,
        "description": "Buffer overflow vulnerabilities can allow attackers to execute arbitrary code or crash the application.",
        "remediation": {
            "description": "Buffer overflows occur when programs write more data to a buffer than it can hold.",
            "steps": [
                "Use safe string functions that perform bounds checking",
                "Implement proper input validation",
                "Use memory-safe programming languages when possible",
                "Enable compiler security flags"
            ],
            "references": [
                "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow",
                "https://cwe.mitre.org/data/definitions/119.html"
            ]
        }
    },
    "path_traversal": {
        "cwe": "CWE-22",
        "cve": None,
        "description": "Path traversal vulnerabilities can allow attackers to access files outside of intended directories.",
        "remediation": {
            "description": "Path traversal occurs when untrusted input is used to construct file paths without proper validation.",
            "steps": [
                "Validate and sanitize file paths",
                "Use path canonicalization",
                "Implement proper access controls",
                "Use safe APIs for file operations"
            ],
            "references": [
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html"
            ]
        }
    }
}

class ScanStatus(BaseModel):
    id: str
    project_name: str
    status: str
    start_time: datetime | None
    end_time: datetime | None
    progress: int
    current_file: str | None
    total_files: int
    total_issues: int
    total_loc: int
    error: str | None

    class Config:
        from_attributes = True

class DashboardStats(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    vulnerability_counts: Dict[str, int]
    recent_scans: List[Dict[str, Any]]
    top_vulnerabilities: List[Dict[str, Any]]
    top_projects: List[Dict[str, Any]]
    daily_scan_counts: List[Dict[str, Any]]

    class Config:
        from_attributes = True

class AnalyzeRequest(BaseModel):
    file_path: str

# Initialize the analyzer
analyzer = VulnerabilityAnalyzer()

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/test-db")
async def test_db(db: Session = Depends(get_db)):
    return {"message": "Database connection successful"}

@app.post("/api/scan")
async def create_scan(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db)
):
    try:
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        scan_dir = os.path.join(data_dir, scan_id)
        
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

        # Clear existing vulnerabilities for this scan
        db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()
        db.commit()

        # Update scan status
        scan.status = "processing"
        scan.start_time = datetime.now()
        db.commit()

        # Get the scan directory
        scan_dir = os.path.join(DATA_DIR, scan_id)
        extracted_dir = os.path.join(scan_dir, "extracted")
        
        # Create scan directory if it doesn't exist
        if not os.path.exists(scan_dir):
            os.makedirs(scan_dir)
            logger.info(f"Created scan directory: {scan_dir}")
        
        # Create extracted directory if it doesn't exist
        if not os.path.exists(extracted_dir):
            os.makedirs(extracted_dir)
            logger.info(f"Created extracted directory: {extracted_dir}")

        # Initialize the analyzer
        analyzer = VulnerabilityAnalyzer()

        # Find all C++ files
        cpp_files = []
        for root, _, files in os.walk(extracted_dir):
            for file in files:
                if file.endswith(('.cpp', '.h', '.hpp', '.c')):
                    file_path = os.path.join(root, file)
                    cpp_files.append(file_path)
                    logger.info(f"Found C++ file: {file_path}")

        scan.total_files = len(cpp_files)
        db.commit()

        # Process each file
        total_issues = 0
        total_loc = 0
        for i, file_path in enumerate(cpp_files):
            try:
                logger.info(f"\nProcessing file {i+1}/{len(cpp_files)}: {file_path}")
                
                # Update progress
                scan.progress = int((i + 1) / len(cpp_files) * 100)
                scan.current_file = os.path.basename(file_path)
                db.commit()

                # Count lines of code
                loc = count_loc(file_path)
                total_loc += loc
                logger.info(f"Lines of code: {loc}")

                # Analyze the file
                logger.info("Starting vulnerability analysis...")
                vulnerabilities = analyzer.analyze_file(file_path)
                total_issues += len(vulnerabilities)
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities")

                # Save vulnerabilities to database
                for vuln in vulnerabilities:
                    db_vuln = Vulnerability(
                        scan_id=scan_id,
                        file=os.path.relpath(file_path, extracted_dir),
                        line=vuln.location.line,
                        rule=vuln.type,
                        message=vuln.description,
                        severity=vuln.severity.value,
                        cwe_id=vuln.cwe_id,
                        cwe_name=CWE_DATABASE.get(vuln.cwe_id, {}).get("name"),
                        cwe_description=CWE_DATABASE.get(vuln.cwe_id, {}).get("description"),
                        source_code=vuln.location.snippet,
                        highlighted_line=vuln.location.line,
                        remediation=vuln.remediation
                    )
                    db.add(db_vuln)

                db.commit()
                logger.info(f"Completed processing file: {file_path}")

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {str(e)}")
                import traceback
                logger.error(traceback.format_exc())
                continue

        # Update scan status
        scan.status = "completed"
        scan.end_time = datetime.now()
        scan.total_issues = total_issues
        scan.total_loc = total_loc
        db.commit()

        logger.info(f"Scan completed: {scan_id}")
        logger.info(f"Total files processed: {len(cpp_files)}")
        logger.info(f"Total issues found: {total_issues}")
        logger.info(f"Total lines of code: {total_loc}")

    except Exception as e:
        logger.error(f"Error processing scan {scan_id}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error = str(e)
            db.commit()
    finally:
        # Remove the task from the task manager
        task_manager.remove_task(scan_id)

@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Convert scan to the format expected by the frontend
    return {
        "scanId": scan.id,
        "projectName": scan.project_name,
        "status": scan.status,
        "startTime": scan.start_time.isoformat() if scan.start_time else None,
        "endTime": scan.end_time.isoformat() if scan.end_time else None,
        "progress": scan.progress,
        "currentFile": scan.current_file,
        "totalFiles": scan.total_files,
        "totalIssues": scan.total_issues,
        "totalLoc": scan.total_loc,
        "error": scan.error
    }

@app.get("/api/scan/{scan_id}/vulnerabilities")
async def get_vulnerabilities(scan_id: str, db: Session = Depends(get_db)):
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    
    # Convert vulnerabilities to the format expected by the frontend
    result = []
    for vuln in vulnerabilities:
        vulnerability = {
            "id": vuln.id,
            "file": vuln.file,
            "line": vuln.line,
            "rule": vuln.rule,
            "message": vuln.message,
            "severity": vuln.severity,
            "isIgnored": bool(vuln.is_ignored),
            "isFalsePositive": bool(vuln.is_false_positive),
            "details": {
                "cwe": None,
                "cve": None,
                "sourceCode": None,
                "remediation": None
            }
        }

        # Add CWE details if available
        if vuln.cwe_id:
            vulnerability["details"]["cwe"] = {
                "id": vuln.cwe_id,
                "name": vuln.cwe_name,
                "description": vuln.cwe_description,
                "mitreUrl": f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html"
            }

        # Add CVE details if available
        if vuln.cve_id:
            vulnerability["details"]["cve"] = {
                "id": vuln.cve_id,
                "description": vuln.cve_description,
                "cvssScore": vuln.cve_cvss_score,
                "nvdUrl": f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}"
            }

        # Add source code details if available
        if vuln.source_code:
            vulnerability["details"]["sourceCode"] = {
                "snippet": vuln.source_code,
                "startLine": max(1, vuln.line - 5),
                "endLine": vuln.line + 5,
                "highlightedLines": [vuln.highlighted_line],
                "fullContent": vuln.source_code,
                "totalLines": len(vuln.source_code.split('\n'))
            }

        # Add remediation details if available
        if vuln.remediation:
            try:
                remediation_data = json.loads(vuln.remediation)
                vulnerability["details"]["remediation"] = remediation_data
            except:
                pass

        result.append(vulnerability)

    return result

@app.get("/api/scan/{scan_id}/source")
async def get_source_code(scan_id: str, file: str, line: int, db: Session = Depends(get_db)):
    try:
        scan_dir = os.path.join(data_dir, scan_id)
        file_path = os.path.join(scan_dir, "extracted", file)
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        with open(file_path, 'r') as f:
            content = f.read()
            lines = content.split('\n')
        
        # Calculate context lines
        context = 10
        start_line = max(1, line - context)
        end_line = min(len(lines), line + context)
        
        return {
            "snippet": "\n".join(lines[start_line-1:end_line]),
            "startLine": start_line,
            "endLine": end_line,
            "highlightedLines": [line],
            "fullContent": content,
            "totalLines": len(lines)
        }
    except Exception as e:
        logger.error(f"Error reading source code: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/vulnerability/{vuln_id}/ignore")
async def mark_vulnerability_ignored(vuln_id: str, ignore: bool):
    """Mark a vulnerability as ignored or unignored."""
    db = next(get_db())
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
            
        vuln.is_ignored = ignore
        db.commit()
        
        return {"message": f"Vulnerability {vuln_id} {'ignored' if ignore else 'unignored'} successfully"}
        
    finally:
        db.close()

@app.post("/api/scan/{scan_id}/vulnerabilities/{vulnerability_id}/false-positive")
async def mark_vulnerability_as_false_positive(
    scan_id: str,
    vulnerability_id: str,
    db: Session = Depends(get_db)
):
    """Mark a vulnerability as a false positive and update the analyzer's patterns."""
    try:
        vulnerability = db.query(Vulnerability).filter(
            Vulnerability.id == vulnerability_id,
            Vulnerability.scan_id == scan_id
        ).first()
        
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Update database
        vulnerability.is_false_positive = 1
        db.commit()
        
        # Update analyzer patterns
        analyzer.mark_as_false_positive(
            vulnerability.rule,
            vulnerability.file,
            vulnerability.line
        )
        
        return {"message": "Vulnerability marked as false positive"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{scan_id}/vulnerabilities/{vulnerability_id}/true-positive")
async def mark_vulnerability_as_true_positive(
    scan_id: str,
    vulnerability_id: str,
    db: Session = Depends(get_db)
):
    """Mark a vulnerability as a true positive and update the analyzer's patterns."""
    try:
        vulnerability = db.query(Vulnerability).filter(
            Vulnerability.id == vulnerability_id,
            Vulnerability.scan_id == scan_id
        ).first()
        
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Update database
        vulnerability.is_false_positive = 0
        db.commit()
        
        # Update analyzer patterns
        analyzer.mark_as_true_positive(
            vulnerability.rule,
            vulnerability.file,
            vulnerability.line
        )
        
        return {"message": "Vulnerability marked as true positive"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

def get_source_code_context(file_path: str, line_number: int, context_lines: int = 5) -> Dict[str, Any]:
    """Get source code context around the vulnerable line."""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)
        
        return {
            "snippet": "".join(lines[start_line:end_line]),
            "startLine": start_line + 1,
            "endLine": end_line,
            "highlightedLines": [line_number]
        }
    except Exception as e:
        logger.error(f"Error reading source code: {str(e)}")
        return None

@app.get("/api/scans", response_model=List[ScanStatus])
async def list_scans(db: Session = Depends(get_db)):
    """List all scans ordered by start_time in descending order"""
    try:
        scans = db.query(Scan).order_by(Scan.start_time.desc()).all()
        return scans
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
        ).join(Vulnerability, Scan.id == Vulnerability.scan_id, isouter=True)\
         .group_by(Scan.id)\
         .order_by(Scan.start_time.desc())\
         .limit(10)\
         .all()

        # Top projects by vulnerability count
        top_projects = db.query(
            Scan.project_name,
            func.count(Vulnerability.id).label('vulnerability_count')
        ).join(Vulnerability, Scan.id == Vulnerability.scan_id)\
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
                try:
                    if isinstance(count.date, datetime):
                        date_str = count.date.strftime("%Y-%m-%d")
                    elif isinstance(count.date, date):
                        date_str = count.date.strftime("%Y-%m-%d")
                    else:
                        date_str = str(count.date)
                    formatted_daily_counts.append({
                        "date": date_str,
                        "count": count.count or 0
                    })
                except Exception as e:
                    logger.error(f"Error formatting date {count.date}: {str(e)}")
                    continue

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
                    "start_time": scan.start_time.strftime("%Y-%m-%dT%H:%M:%S") if isinstance(scan.start_time, datetime) else str(scan.start_time),
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

@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan and all its associated data"""
    try:
        # Delete vulnerabilities first (due to foreign key constraint)
        db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()
        
        # Delete the scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        db.delete(scan)
        db.commit()
        
        # Delete scan directory if it exists
        scan_dir = os.path.join(data_dir, scan_id)
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)
        
        return {"message": "Scan deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/analyze")
async def analyze_file(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """Analyze a single file for vulnerabilities."""
    try:
        # Initialize the analyzer
        analyzer = VulnerabilityAnalyzer()
        
        # Check if file exists
        if not os.path.exists(request.file_path):
            raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")
            
        # Analyze the file
        print(f"\nAnalyzing file: {request.file_path}")
        vulnerabilities = analyzer.analyze_file(request.file_path)
        
        # Create a scan record
        scan = Scan(
            id=str(uuid.uuid4()),
            project_name=os.path.basename(request.file_path),
            status="completed",
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            progress=100,
            current_file=request.file_path,
            total_files=1,
            total_issues=len(vulnerabilities),
            total_loc=count_loc(request.file_path)
        )
        db.add(scan)
        
        # Add vulnerabilities to database
        for vuln in vulnerabilities:
            db_vuln = Vulnerability(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                file=request.file_path,
                line=vuln.location.line,
                rule=vuln.type,
                message=vuln.description,
                severity=vuln.severity,
                is_ignored=False,
                is_false_positive=False,
                cwe_id=vuln.cwe_id,
                source_code=vuln.location.snippet,
                remediation=vuln.remediation
            )
            db.add(db_vuln)
        
        db.commit()
        
        return {
            "scan_id": scan.id,
            "vulnerabilities": [
                {
                    "id": str(uuid.uuid4()),
                    "type": v.type,
                    "severity": v.severity,
                    "description": v.description,
                    "location": {
                        "file": v.location.file,
                        "line": v.location.line,
                        "column": v.location.column,
                        "snippet": v.location.snippet
                    },
                    "cwe_id": v.cwe_id,
                    "remediation": v.remediation,
                    "score": v.score,
                    "confidence": v.confidence
                }
                for v in vulnerabilities
            ]
        }
        
    except Exception as e:
        logger.error(f"Error analyzing file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000) 