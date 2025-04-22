import os
import shutil
import zipfile
from pathlib import Path
from typing import Optional
from fastapi import UploadFile
from ..config import SCANS_DIR

class FileService:
    def __init__(self):
        self.base_dir = SCANS_DIR

    def save_uploaded_file(self, file: UploadFile, scan_id: str) -> Optional[str]:
        """Salva um arquivo enviado e retorna o caminho"""
        try:
            scan_dir = self.base_dir / str(scan_id)
            scan_dir.mkdir(parents=True, exist_ok=True)
            
            file_path = scan_dir / file.filename
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            return str(file_path)
        except Exception as e:
            print(f"Error saving file: {str(e)}")
            return None

    def extract_zip(self, zip_path: str, destination: str) -> bool:
        """Extrai um arquivo ZIP para o diretório de destino"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(destination)
            return True
        except Exception as e:
            print(f"Error extracting ZIP: {str(e)}")
            return False

    def cleanup_scan_files(self, scan_id: str) -> bool:
        """Remove os arquivos de um scan"""
        try:
            scan_dir = self.base_dir / str(scan_id)
            if scan_dir.exists():
                shutil.rmtree(scan_dir)
            return True
        except Exception as e:
            print(f"Error cleaning up scan files: {str(e)}")
            return False 