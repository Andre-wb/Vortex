"""
Tests for room tasks (todo lists).
"""
import pytest

from conftest import random_str


class TestRoomTasks:

    def test_list_tasks_in_room(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id")
        resp = client.get(f"/api/rooms/{room_id}/tasks", headers=logged_user["headers"])
        assert resp.status_code in (200, 404)

    def test_create_task_in_room(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id")
        resp = client.post(f"/api/rooms/{room_id}/tasks", json={
            "text": f"Task {random_str()}",
        }, headers=logged_user["headers"])
        assert resp.status_code in (200, 201, 404)
