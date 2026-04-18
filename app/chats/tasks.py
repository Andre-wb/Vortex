"""
app/chats/tasks.py — Collaborative task list for group chats.

Allows room members to create, toggle, update, and delete tasks within a room.
Each task has a text, optional assignee, and done/not-done status.

Endpoints:
  GET    /api/rooms/{room_id}/tasks              — list all tasks for the room
  POST   /api/rooms/{room_id}/tasks              — create a new task
  PUT    /api/rooms/{room_id}/tasks/{task_id}    — toggle done, update text, assign
  DELETE /api/rooms/{room_id}/tasks/{task_id}    — delete task (creator or admin/owner)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import RoomMember, RoomRole, RoomTask
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/rooms", tags=["tasks"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_member(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id,
        RoomMember.is_banned == False,
    ).first()
    if not m:
        raise HTTPException(403, "You are not a member of this room")
    return m


def _task_dict(t: RoomTask) -> dict:
    """Serialize a RoomTask to a JSON-friendly dict."""
    return {
        "id":           t.id,
        "room_id":      t.room_id,
        "creator_id":   t.creator_id,
        "creator_name": (t.creator.display_name or t.creator.username) if t.creator else None,
        "assignee_id":  t.assignee_id,
        "assignee_name": (t.assignee.display_name or t.assignee.username) if t.assignee else None,
        "text":         t.text,
        "is_done":      t.is_done,
        "created_at":   t.created_at.isoformat() if t.created_at else None,
    }


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class TaskCreate(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)
    assignee_id: int | None = None


class TaskUpdate(BaseModel):
    text: str | None = Field(None, min_length=1, max_length=500)
    is_done: bool | None = None
    assignee_id: int | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/{room_id}/tasks")
async def list_tasks(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all tasks for the room, ordered by creation time."""
    _require_member(room_id, u.id, db)
    tasks = (
        db.query(RoomTask)
        .filter(RoomTask.room_id == room_id)
        .order_by(RoomTask.is_done.asc(), RoomTask.created_at.desc())
        .all()
    )
    return {"tasks": [_task_dict(t) for t in tasks]}


@router.post("/{room_id}/tasks")
async def create_task(
    room_id: int,
    body: TaskCreate,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new task in the room."""
    _require_member(room_id, u.id, db)

    # Validate assignee is a room member (if provided)
    if body.assignee_id is not None:
        assignee_member = db.query(RoomMember).filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == body.assignee_id,
            RoomMember.is_banned == False,
        ).first()
        if not assignee_member:
            raise HTTPException(400, "Assigned user is not a room member")

    task = RoomTask(
        room_id=room_id,
        creator_id=u.id,
        assignee_id=body.assignee_id,
        text=body.text.strip(),
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return _task_dict(task)


@router.put("/{room_id}/tasks/{task_id}")
async def update_task(
    room_id: int,
    task_id: int,
    body: TaskUpdate,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update a task: toggle done, change text, or reassign."""
    _require_member(room_id, u.id, db)

    task = db.query(RoomTask).filter(
        RoomTask.id == task_id,
        RoomTask.room_id == room_id,
    ).first()
    if not task:
        raise HTTPException(404, "Task not found")

    if body.is_done is not None:
        task.is_done = body.is_done
    if body.text is not None:
        task.text = body.text.strip()
    if body.assignee_id is not None:
        # Validate assignee is a room member
        if body.assignee_id != 0:
            assignee_member = db.query(RoomMember).filter(
                RoomMember.room_id == room_id,
                RoomMember.user_id == body.assignee_id,
                RoomMember.is_banned == False,
            ).first()
            if not assignee_member:
                raise HTTPException(400, "Assigned user is not a room member")
            task.assignee_id = body.assignee_id
        else:
            task.assignee_id = None

    db.commit()
    db.refresh(task)
    return _task_dict(task)


@router.delete("/{room_id}/tasks/{task_id}")
async def delete_task(
    room_id: int,
    task_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a task. Only the creator or an admin/owner can delete."""
    member = _require_member(room_id, u.id, db)

    task = db.query(RoomTask).filter(
        RoomTask.id == task_id,
        RoomTask.room_id == room_id,
    ).first()
    if not task:
        raise HTTPException(404, "Task not found")

    # Only creator, admin, or owner can delete
    if task.creator_id != u.id and member.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        raise HTTPException(403, "Only the task creator or an admin can delete it")

    db.delete(task)
    db.commit()
    return {"deleted": True, "task_id": task_id}
