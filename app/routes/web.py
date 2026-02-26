from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path

router = APIRouter()

templates_path = Path(__file__).parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))

@router.get("/")
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@router.get("/stats")
async def get_stats():
    from app.services.chat_service import chat_service
    import time
    import hashlib
    import vortex_chat

    # Speed test rust vs python
    test_message = b"x" * 1000

    # Python hash
    start = time.time()
    for _ in range(10000):
        hashlib.sha256(test_message).hexdigest()
    py_time = time.time() - start

    # Rust hash
    start = time.time()
    for _ in range(10000):
        vortex_chat.hash_message(test_message)
    rust_time = time.time() - start

    return {
        "chat_stats": chat_service.chat_stats.get_stats(),
        "benchmark": {
            "python_hash_10000": f"{py_time:.3f} sec",
            "rust_hash_10000": f"{rust_time:.3f} sec",
            "speedup": f"{py_time/rust_time:.1f}x"
        },
        "version": vortex_chat.VERSION
    }