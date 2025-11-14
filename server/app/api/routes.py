from fastapi import APIRouter, Request, Response, Query
from app.middleware import get_user_id_from_request, set_user_cookie
from app.database import db
from app.schemas import (
    PortScanRequest,
    PortScanResponse,
    SqlScanRequest,
    SqlScanResponse,
    XssScanRequest,
    XssScanResponse,
    HeaderScanRequest,
    HeaderScanResponse,
    DirectoryScanRequest,
    DirectoryScanResponse,
    OsintRequest,
    OsintResponse,
    CredentialAuditRequest,
    CredentialAuditResponse,
    WappalyzerRequest,
    WappalyzerResponse,
    HistoryEntry,
    HistoryRequest,
    HistoryResponse,
    UserStats,
    DeleteResponse,
)
from ..services import mock_scans

router = APIRouter(prefix="", tags=["EduScan"])


def _wrap_call(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/health", tags=["System"])
def health_check():
    return {"status": "ok"}


@router.post("/port-scan", response_model=PortScanResponse)
def run_port_scan(payload: PortScanRequest):
    return _wrap_call(mock_scans.generate_port_scan, payload.model_dump())


@router.post("/sqli-scan", response_model=SqlScanResponse)
def run_sql_scan(payload: SqlScanRequest):
    return _wrap_call(mock_scans.generate_sql_scan, payload.model_dump())


@router.post("/xss-scan", response_model=XssScanResponse)
def run_xss_scan(payload: XssScanRequest):
    return _wrap_call(mock_scans.generate_xss_scan, payload.model_dump())


@router.post("/header-analyzer", response_model=HeaderScanResponse)
def run_header_scan(payload: HeaderScanRequest):
    return _wrap_call(mock_scans.generate_header_scan, str(payload.url))


@router.post("/directory-buster", response_model=DirectoryScanResponse)
def run_directory_scan(payload: DirectoryScanRequest):
    return _wrap_call(mock_scans.generate_directory_scan, payload.model_dump())


@router.post("/osint", response_model=OsintResponse)
def run_osint(payload: OsintRequest):
    return _wrap_call(mock_scans.generate_osint, payload.model_dump())





@router.post("/credential-audit", response_model=CredentialAuditResponse)
def run_credential_audit(payload: CredentialAuditRequest):
    return _wrap_call(mock_scans.generate_credential_audit, payload.model_dump())


@router.post("/wappalyzer", response_model=WappalyzerResponse)
def run_wappalyzer(payload: WappalyzerRequest):
    return _wrap_call(mock_scans.generate_wappalyzer_scan, payload.model_dump())


# History Management Endpoints
@router.get("/history", response_model=HistoryResponse)
def get_scan_history(
    request: Request,
    response: Response,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(5, ge=1, le=20, description="Items per page")
):
    """Get paginated scan history for the user."""
    user_id = get_user_id_from_request(request)
    set_user_cookie(response, user_id)
    
    history_data = db.get_history(user_id, page, per_page)
    return history_data


@router.post("/history", response_model=HistoryEntry)
def add_history_entry(request: Request, response: Response, payload: HistoryRequest):
    """Add a new scan history entry."""
    user_id = get_user_id_from_request(request)
    set_user_cookie(response, user_id)
    
    entry = db.add_history_entry(user_id, payload.entry.model_dump())
    return entry


@router.delete("/history/{entry_id}", response_model=DeleteResponse)
def delete_history_entry(request: Request, response: Response, entry_id: str):
    """Delete a specific history entry."""
    user_id = get_user_id_from_request(request)
    set_user_cookie(response, user_id)
    
    success = db.delete_history_entry(user_id, entry_id)
    
    if success:
        return {"success": True, "message": "History entry deleted successfully"}
    else:
        return {"success": False, "message": "History entry not found"}


@router.delete("/history", response_model=DeleteResponse)
def clear_all_history(request: Request, response: Response):
    """Clear all history entries for the user."""
    user_id = get_user_id_from_request(request)
    set_user_cookie(response, user_id)
    
    success = db.clear_history(user_id)
    
    return {"success": True, "message": "All history entries cleared"}


@router.get("/user/stats", response_model=UserStats)
def get_user_stats(request: Request, response: Response):
    """Get user statistics and info."""
    user_id = get_user_id_from_request(request)
    set_user_cookie(response, user_id)
    
    stats = db.get_user_stats(user_id)
    return stats


# Legacy endpoint for backward compatibility
@router.get("/scan-history")
def list_scan_history_legacy(request: Request, response: Response, seed: int = 5):
    """Legacy endpoint - redirects to new history system."""
    user_id = get_user_id_from_request(request)
    set_user_cookie(response, user_id)
    
    # Return user's actual history instead of mock data
    history_data = db.get_history(user_id, 1, 10)
    return {"items": history_data["items"]}
