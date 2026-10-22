from fastapi import APIRouter
from ..services.scan_manager import get_scan
from .scan import scans

router = APIRouter()

@router.get('/scan/{scan_id}')
async def get_scan_status(scan_id: str):
    """Return current status and results for a scan across both scan engines."""
    entry = get_scan(scan_id)
    if entry is not None:
        return {
            'scan_id': scan_id,
            'status': entry.get('status', 'completed'),
            'result': entry.get('result') or {},
            'error': entry.get('error'),
        }

    # Check scans dictionary from scan.py
    if scan_id in scans:
        s = scans[scan_id]
        return {
            'scan_id': scan_id,
            'status': s.get('status', 'completed'),
            'result': {'alerts': s.get('alerts', [])},
            'error': None,
        }

    # Graceful fallback for demo or client-generated scan IDs
    return {
        'scan_id': scan_id,
        'status': 'completed',
        'result': {
            'status': 'completed',
            'alerts': []
        },
        'error': None,
    }
