from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import tempfile
import os
import shutil
import zipfile
from pathlib import Path

from analyzer.core import VulnerabilityAnalyzer, Vulnerability, Severity

app = FastAPI(title="cxSAST API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the analyzer
analyzer = VulnerabilityAnalyzer()

class ScanRequest(BaseModel):
    source_type: str
    source_path: str
    exclude_paths: List[str] = []

class ScanResponse(BaseModel):
    total_issues: int
    unique_vulns: int
    vulnerabilities: List[Vulnerability]
    metrics: dict

@app.post("/api/scan", response_model=ScanResponse)
async def scan_code(scan_request: ScanRequest):
    try:
        vulnerabilities = []
        
        if scan_request.source_type == "LOCAL":
            # Analyze local directory
            if not os.path.exists(scan_request.source_path):
                raise HTTPException(status_code=400, detail="Source path does not exist")
            
            vulnerabilities = analyzer.analyze_directory(
                scan_request.source_path,
                file_patterns=["*.c", "*.cpp", "*.h", "*.hpp"]
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported source type")

        # Calculate metrics
        metrics = {
            "critical": len([v for v in vulnerabilities if v.severity == Severity.CRITICAL]),
            "high": len([v for v in vulnerabilities if v.severity == Severity.HIGH]),
            "medium": len([v for v in vulnerabilities if v.severity == Severity.MEDIUM]),
            "low": len([v for v in vulnerabilities if v.severity == Severity.LOW])
        }

        return ScanResponse(
            total_issues=len(vulnerabilities),
            unique_vulns=len(set(v.type for v in vulnerabilities)),
            vulnerabilities=vulnerabilities,
            metrics=metrics
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/upload")
async def upload_and_scan(file: UploadFile = File(...)):
    try:
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, file.filename)
            
            # Save uploaded file
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # If it's a ZIP file, extract it
            if file.filename.endswith('.zip'):
                extract_dir = os.path.join(temp_dir, "extracted")
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                scan_path = extract_dir
            else:
                scan_path = file_path

            # Analyze the code
            vulnerabilities = analyzer.analyze_directory(
                scan_path,
                file_patterns=["*.c", "*.cpp", "*.h", "*.hpp"]
            )

            # Calculate metrics
            metrics = {
                "critical": len([v for v in vulnerabilities if v.severity == Severity.CRITICAL]),
                "high": len([v for v in vulnerabilities if v.severity == Severity.HIGH]),
                "medium": len([v for v in vulnerabilities if v.severity == Severity.MEDIUM]),
                "low": len([v for v in vulnerabilities if v.severity == Severity.LOW])
            }

            return ScanResponse(
                total_issues=len(vulnerabilities),
                unique_vulns=len(set(v.type for v in vulnerabilities)),
                vulnerabilities=vulnerabilities,
                metrics=metrics
            )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 