from datetime import datetime, timedelta
from typing import Optional
from jose import jwt

# Security configurations
SECRET_KEY = "your-secret-key-here"  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Default credentials
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return plain_password == DEFAULT_PASSWORD

def get_password_hash(password: str) -> str:
    return password  # For development, we're just storing the plain password

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt 