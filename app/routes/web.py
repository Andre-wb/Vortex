from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path
import vortex_chat

router = APIRouter()

templates_path = Path(__file__).parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))

@router.get("/")
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@router.get("/peers")
async def peers():
    return vortex_chat.get_peers()