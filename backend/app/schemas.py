from pydantic import BaseModel
from typing import List, Optional

# Existing scan schemas
class ScanRequest(BaseModel):
    target_url: str

class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str

class FindingResponse(BaseModel):
    id: int
    cwe: Optional[str]
    owasp_category: Optional[str]
    severity: Optional[str]
    url: Optional[str]
    param: Optional[str]
    evidence: Optional[str]
    name: Optional[str] = None

class ExplanationResponse(BaseModel):
    plain_text: Optional[str]
    attack_path: Optional[str]
    remediation: Optional[str]

# New workflow response models
class UploadResponse(BaseModel):
    upload_id: str
    message: str

class MissingResponse(BaseModel):
    missing_files: List[str]

class SecurityFinding(BaseModel):
    cwe: Optional[str]
    severity: Optional[str]
    description: Optional[str]
    url: Optional[str]

class SecurityResponse(BaseModel):
    findings: List[SecurityFinding]

class GeneratedFile(BaseModel):
    filename: str
    content: str

class GenerationResponse(BaseModel):
    generated: List[GeneratedFile]

class CleaningResponse(BaseModel):
    cleaned: List[GeneratedFile]

class IntegrationResponse(BaseModel):
    message: str
    updated_repo_path: Optional[str] = None
