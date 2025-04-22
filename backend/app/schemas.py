from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class UserResponse(User):
    pass

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ScanBase(BaseModel):
    project_name: str

class ScanCreate(ScanBase):
    pass

class Scan(ScanBase):
    id: int
    user_id: int
    start_time: datetime
    end_time: Optional[datetime]
    status: str
    total_files: int
    total_loc: int
    total_issues: int

    class Config:
        from_attributes = True

class VulnerabilityBase(BaseModel):
    file_path: str
    line_number: int
    vulnerability_type: str
    severity: str
    description: str
    remediation: str
    rule: Optional[str] = None

class VulnerabilityCreate(VulnerabilityBase):
    scan_id: int

class Vulnerability(VulnerabilityBase):
    id: int
    scan_id: int

    class Config:
        from_attributes = True 