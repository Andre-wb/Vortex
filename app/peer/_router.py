"""
app/peer/_router.py — Shared APIRouter for all peer sub-modules.
"""
from fastapi import APIRouter

router = APIRouter(prefix="/api/peers", tags=["peers"])
