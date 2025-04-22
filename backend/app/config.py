import os
from pathlib import Path

# Diretório base para uploads
UPLOAD_DIR = Path("uploads")
SCANS_DIR = UPLOAD_DIR / "scans"
EXTRACTED_DIR = UPLOAD_DIR / "extracted"

def create_directories():
    """Cria os diretórios necessários para a aplicação."""
    for directory in [UPLOAD_DIR, SCANS_DIR, EXTRACTED_DIR]:
        directory.mkdir(parents=True, exist_ok=True)

# Diretórios
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "scans.db"

# Configurações do Semgrep
SEMGREP_CONFIG = {
    "rules": [
        {
            "id": "insecure-crypto",
            "pattern": "crypto.createCipher",
            "message": "Use of insecure crypto function",
            "severity": "ERROR"
        },
        {
            "id": "sql-injection",
            "pattern": "execute($query)",
            "message": "Potential SQL injection vulnerability",
            "severity": "ERROR"
        }
    ],
    "exclude": [
        "node_modules",
        "venv",
        ".git",
        "__pycache__"
    ]
}

# Configurações de segurança
SECRET_KEY = "your-secret-key-here"  # Change in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configurações do banco de dados
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Criar diretórios necessários
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(SCANS_DIR, exist_ok=True) 