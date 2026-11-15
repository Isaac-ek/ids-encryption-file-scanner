"""Workspace totals, filtered event history and authenticated exports."""
import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, JSONResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from api.auth import get_current_user, DBUser
from api.database import get_db
from api.models import DBThreatAlert, DBScanRun, DBFileCheck

router = APIRouter(prefix='/api/workspace', tags=['Workspace'])

def event_dict(event):
    return {key: getattr(event, key) for key in ['id', 'timestamp', 'alert_type', 'origin', 'source_ip', 'destination_ip']}

def event_query(db, date=None, alert_type=None, src=None, dst=None, origin=None):
    query = db.query(DBThreatAlert)
    for column, value in [('alert_type', alert_type), ('origin', origin)]:
        if value: query = query.filter(getattr(DBThreatAlert, column) == value)
    if date: query = query.filter(DBThreatAlert.timestamp.startswith(date))
    if src: query = query.filter(DBThreatAlert.source_ip.contains(src, autoescape=True))
    if dst: query = query.filter(DBThreatAlert.destination_ip.contains(dst, autoescape=True))
    return query

@router.get('/overview')
def overview(db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    counts = {origin: count for origin, count in db.query(DBThreatAlert.origin, func.count(DBThreatAlert.id)).group_by(DBThreatAlert.origin).all()}
    classes = {label: count for label, count in db.query(DBThreatAlert.alert_type, func.count(DBThreatAlert.id)).group_by(DBThreatAlert.alert_type).all()}
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    recent = db.query(DBThreatAlert).order_by(DBThreatAlert.id.desc()).limit(6).all()
    return {
        'total_events': sum(counts.values()), 'origins': counts, 'classes': classes,
        'last_24_hours': db.query(DBThreatAlert).filter(DBThreatAlert.timestamp >= cutoff).count(),
        'website_checks': db.query(DBScanRun).count(), 'file_checks': db.query(DBFileCheck).count(),
        'recent': [event_dict(event) for event in recent],
        'latest_sensor_event': db.query(func.max(DBThreatAlert.timestamp)).filter(DBThreatAlert.origin == 'sensor').scalar(),
    }

@router.get('/events')
def events(date: str | None = Query(None, max_length=10), alert_type: str | None = Query(None, max_length=100), src: str | None = Query(None, max_length=100), dst: str | None = Query(None, max_length=100), origin: str | None = Query(None, max_length=50), page: int = Query(1, ge=1), per_page: int = Query(25, ge=1, le=100), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    query = event_query(db, date, alert_type, src, dst, origin)
    total = query.count()
    rows = query.order_by(DBThreatAlert.id.desc()).offset((page-1)*per_page).limit(per_page).all()
    return {'items': [event_dict(row) for row in rows], 'total': total, 'page': page, 'per_page': per_page}

@router.get('/events/export')
def export_events(format: Literal['csv', 'json'] = 'csv', date: str | None = Query(None, max_length=10), alert_type: str | None = Query(None, max_length=100), src: str | None = Query(None, max_length=100), dst: str | None = Query(None, max_length=100), origin: str | None = Query(None, max_length=50), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    rows = [event_dict(row) for row in event_query(db, date, alert_type, src, dst, origin).order_by(DBThreatAlert.id.desc()).limit(10000).all()]
    headers = {'Content-Disposition': f'attachment; filename="security-events.{format}"', 'X-Export-Limit': '10000'}
    if format == 'json': return JSONResponse(rows, headers=headers)
    output = io.StringIO(newline='')
    fields = ['id', 'timestamp', 'alert_type', 'origin', 'source_ip', 'destination_ip']
    writer = csv.DictWriter(output, fieldnames=fields); writer.writeheader()
    for row in rows:
        # Spreadsheet consumers must not interpret user-supplied cells as formulas.
        writer.writerow({key: "'" + value if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else value for key, value in row.items()})
    return Response(output.getvalue(), media_type='text/csv', headers=headers)
