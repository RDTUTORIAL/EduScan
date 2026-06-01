from __future__ import annotations

from typing import List, Literal, Optional, Dict, Any
from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl


class PortEntry(BaseModel):
    port: int
    status: Literal["open", "closed", "filtered"]
    service: str
    version: str


class PortScanRequest(BaseModel):
    target: str = Field(..., min_length=3, description="Hostname atau IP target.")
    mode: Literal["common", "custom"] = "common"
    custom_ports: Optional[str] = Field(None, description="Daftar port dipisah koma jika mode custom.")


class PortScanResponse(BaseModel):
    target: str
    table: List[PortEntry]
    summary: dict
    risk_score: int = Field(..., ge=0, le=100)
    command: str
    insights: List[str] = []
    analysis: List[str] = []
    recommendations: List[str] = []


class SqlScanRequest(BaseModel):
    url: HttpUrl
    parameter: str = Field("id", min_length=1)
    payload_type: Literal["error", "union", "blind"] = "error"


class SqlScanResponse(BaseModel):
    url: HttpUrl
    payload_type: str
    table: List[dict]
    risk_score: int
    mitigation: str
    diff_original: str
    diff_patched: str
    recommendations: List[str] = []
    log: List[str] = []


class XssScanRequest(BaseModel):
    url: HttpUrl


class XssScanResponse(BaseModel):
    url: HttpUrl
    risk_score: int
    detection: str
    recommendation: Optional[str] = None
    findings: List[dict] = []


class HeaderScanRequest(BaseModel):
    url: HttpUrl


class HeaderScanResponse(BaseModel):
    url: HttpUrl
    headers: List[dict]
    risk_score: int
    coverage: int
    critical_coverage: str
    security_level: str
    tool_note: str
    recommendations: List[str] = []
    total_score: int
    max_score: int
    logs: List[str] = []
    nmap_enabled: bool = False


class DirectoryScanRequest(BaseModel):
    base_url: HttpUrl
    # Pilihan wordlist yang didukung oleh dirbuster (ffuf)
    wordlist: Literal[
        "admin",
        "config",
        "env",
        "fuzz",
        "wp-content",
        "phpunit",
        "phpmyadmin",
    ] = "admin"


class DirectoryScanResponse(BaseModel):
    base_url: HttpUrl
    wordlist: str
    entries: List[dict]
    risk_score: int
    recommendations: List[str] = []


class OsintRequest(BaseModel):
    tab: Literal["phone", "domain", "email", "username"] = "phone"
    value: str = Field(..., min_length=3)
    # Optional cookie for Truecaller scraping
    truecaller_cookie: Optional[str] = None


class OsintResponse(BaseModel):
    tab: str
    value: str
    timestamp: str
    confidence: str
    # Optional tool integration results
    tools: List[dict] = []
    summary: Optional[dict] = None
    summary_text: Optional[str] = None
    results: List[dict] = []
    tool_outputs: List[dict] = []



class WebSurfaceRequest(BaseModel):
    url: HttpUrl
    techniques: List[str] = Field(default_factory=list)


class WebSurfaceResponse(BaseModel):
    url: HttpUrl
    techniques: List[str]
    vulnerabilities: List[dict]
    spider: List[dict]
    risk_score: int
    tools: List[dict]
    note: Optional[str] = None
    recommendations: List[str] = []


class CredentialAuditRequest(BaseModel):
    samples: List[str] = Field(..., min_items=1)


class CredentialAuditResponse(BaseModel):
    total: int
    weak: List[str]
    weak_detailed: List[dict] = []
    reused: List[str]
    reused_detailed: List[dict] = []
    crackable_hashes: List[str] = []
    hash_analysis: List[dict] = []
    policy: dict
    complexity_stats: dict = {}
    risk_score: int
    recommendations: List[str] = []
    jtr_commands: List[str] = []
    tools_suggested: List[str] = []
    tools_used: List[str] = []
    tool_results: dict = {}


class HistoryItem(BaseModel):
    id: str
    tool: str
    target: str
    risk: int
    timestamp: str
    status: str


class HistoryResponse(BaseModel):
    items: List[HistoryItem]


class WappalyzerRequest(BaseModel):
    domain: str = Field(..., min_length=3, description="Domain untuk dianalisis teknologinya")


class WappalyzerResponse(BaseModel):
    domain: str
    technologies: dict = Field(default_factory=dict, description="Teknologi yang terdeteksi per kategori")
    total_found: int = Field(0, description="Total teknologi yang ditemukan")
    timestamp: str


# History Management Schemas
class HistoryEntry(BaseModel):
    id: str
    tool: str
    target: str
    risk: int
    timestamp: str
    status: str
    result: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None

class HistoryRequest(BaseModel):
    entry: HistoryEntry

class PaginationInfo(BaseModel):
    page: int
    per_page: int
    total: int
    total_pages: int
    has_next: bool
    has_prev: bool

class HistoryResponse(BaseModel):
    items: List[HistoryEntry]
    pagination: PaginationInfo

class UserStats(BaseModel):
    user_id: str
    created_at: str
    last_active: str
    total_scans: int
    tools_used: int
    tools_list: List[str]
    recent_scans: List[HistoryEntry]

class DeleteResponse(BaseModel):
    success: bool
    message: str
