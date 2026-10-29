import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.database.session import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import (
    AnalyzeRequest, ScanResponse, ScanHistoryResponse,
    ScanHistoryItem, StatsResponse, ThreatIntelResult
)
from app.services.analyzer import analyze_url
from app.config import settings

router = APIRouter(prefix="/api")

@router.get("/health", tags=["System"])
def health_check():
    """Health status and configuration info."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "threat_intel_configured": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

@router.post("/analyze", response_model=ScanResponse, tags=["Security Analysis"])
async def analyze_url_endpoint(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Submits a URL for deep security, heuristic, and threat analysis.
    Stores the result in scan history.
    """
    try:
        report = await analyze_url(request.url)
    except ValueError as ve:
        raise HTTPException(
            status_code=422,
            detail=str(ve)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while analyzing the URL."
        )

    # Persist in SQLite
    try:
        record = ScanRecord(
            scan_id=report["scan_id"],
            submitted_url=report["submitted_url"],
            normalized_url=report["normalized_url"],
            hostname=report["hostname"],
            domain=report["domain"],
            risk_score=report["risk_score"],
            risk_level=report["risk_level"],
            analysis_summary=report["summary"],
            indicators_json=json.dumps(report["indicators"]),
            url_details_json=json.dumps(report["url_details"]),
            recommendations_json=json.dumps(report["recommendations"]),
            threat_intelligence_status=report["threat_intelligence"]["status"],
            threat_intel_json=json.dumps(report["threat_intelligence"]),
            analyzed_at=datetime.utcnow()
        )
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception as db_exc:
        db.rollback()
        # Continue returning report even if history save fails
        print(f"Failed to persist scan history: {db_exc}")

    return report

@router.get("/history", response_model=ScanHistoryResponse, tags=["Scan History"])
def get_scan_history(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search term for URL or hostname"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    db: Session = Depends(get_db)
):
    """Retrieves paginated scan history with optional search and filtering."""
    query = db.query(ScanRecord)

    if search:
        search_filter = f"%{search.strip()}%"
        query = query.filter(
            (ScanRecord.submitted_url.ilike(search_filter)) |
            (ScanRecord.normalized_url.ilike(search_filter)) |
            (ScanRecord.hostname.ilike(search_filter))
        )

    if risk_level:
        query = query.filter(ScanRecord.risk_level == risk_level.lower())

    total = query.count()
    records = query.order_by(desc(ScanRecord.analyzed_at)).offset((page - 1) * limit).limit(limit).all()

    items = [
        ScanHistoryItem(
            scan_id=r.scan_id,
            submitted_url=r.submitted_url,
            normalized_url=r.normalized_url,
            hostname=r.hostname,
            domain=r.domain,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            summary=r.analysis_summary,
            analyzed_at=r.analyzed_at.isoformat() + "Z" if r.analyzed_at else ""
        )
        for r in records
    ]

    return ScanHistoryResponse(
        items=items,
        total=total,
        page=page,
        limit=limit
    )

@router.get("/history/{scan_id}", response_model=ScanResponse, tags=["Scan History"])
def get_scan_by_id(scan_id: str, db: Session = Depends(get_db)):
    """Retrieves the full analysis report for a specific scan ID."""
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found."
        )

    try:
        indicators = json.loads(record.indicators_json)
        url_details = json.loads(record.url_details_json)
        recommendations = json.loads(record.recommendations_json)
        threat_intelligence = json.loads(record.threat_intel_json)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deserializing historical scan data."
        )

    return ScanResponse(
        scan_id=record.scan_id,
        submitted_url=record.submitted_url,
        normalized_url=record.normalized_url,
        hostname=record.hostname,
        domain=record.domain or record.hostname,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        summary=record.analysis_summary,
        indicators=indicators,
        url_details=url_details,
        recommendations=recommendations,
        threat_intelligence=ThreatIntelResult(**threat_intelligence),
        analyzed_at=record.analyzed_at.isoformat() + "Z" if record.analyzed_at else ""
    )

@router.delete("/history/{scan_id}", tags=["Scan History"])
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Deletes a specific scan record from the database."""
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found."
        )

    db.delete(record)
    db.commit()
    return {"message": "Scan record successfully deleted.", "scan_id": scan_id}

@router.get("/stats", response_model=StatsResponse, tags=["Analytics & Statistics"])
def get_security_stats(db: Session = Depends(get_db)):
    """
    Computes real aggregate security statistics derived directly from stored scan records.
    Displays realistic zero/empty states if no records exist.
    """
    total_scans = db.query(func.count(ScanRecord.scan_id)).scalar() or 0

    if total_scans == 0:
        return StatsResponse(
            total_scans=0,
            critical_risk=0,
            high_risk=0,
            medium_risk=0,
            low_risk=0,
            avg_risk_score=0.0,
            risk_distribution={"low": 0, "moderate": 0, "high": 0, "critical": 0},
            recent_scans=[]
        )

    critical_count = db.query(func.count(ScanRecord.scan_id)).filter(ScanRecord.risk_level == "critical").scalar() or 0
    high_count = db.query(func.count(ScanRecord.scan_id)).filter(ScanRecord.risk_level == "high").scalar() or 0
    medium_count = db.query(func.count(ScanRecord.scan_id)).filter(ScanRecord.risk_level == "moderate").scalar() or 0
    low_count = db.query(func.count(ScanRecord.scan_id)).filter(ScanRecord.risk_level == "low").scalar() or 0

    avg_score = db.query(func.avg(ScanRecord.risk_score)).scalar() or 0.0

    recent_records = db.query(ScanRecord).order_by(desc(ScanRecord.analyzed_at)).limit(5).all()
    recent_items = [
        ScanHistoryItem(
            scan_id=r.scan_id,
            submitted_url=r.submitted_url,
            normalized_url=r.normalized_url,
            hostname=r.hostname,
            domain=r.domain,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            summary=r.analysis_summary,
            analyzed_at=r.analyzed_at.isoformat() + "Z" if r.analyzed_at else ""
        )
        for r in recent_records
    ]

    return StatsResponse(
        total_scans=total_scans,
        critical_risk=critical_count,
        high_risk=high_count,
        medium_risk=medium_count,
        low_risk=low_count,
        avg_risk_score=round(float(avg_score), 1),
        risk_distribution={
            "low": low_count,
            "moderate": medium_count,
            "high": high_count,
            "critical": critical_count
        },
        recent_scans=recent_items
    )
