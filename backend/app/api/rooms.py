"""Rooms router was unrelated demo hotel code; neutralised to a health stub."""
from fastapi import APIRouter

router = APIRouter(tags=["misc"])


@router.get("/rooms")
async def rooms():
    return {"message": "Not used by Sentinel", "rooms": []}
