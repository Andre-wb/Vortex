"""
Locust load test for Vortex Chat.

Usage:
    pip install locust
    locust -f deploy/loadtest/locustfile.py --host http://localhost:9000
    locust -f deploy/loadtest/locustfile.py --host http://localhost:9000 --headless -u 500 -r 50 -t 5m
"""

import secrets
import string
import json
from locust import HttpUser, task, between, events


def _random_str(n=10):
    return ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _random_digits(n=7):
    return ''.join(secrets.choice(string.digits) for _ in range(n))


class VortexUser(HttpUser):
    """Simulates a typical Vortex user: register, login, create room, send messages."""

    wait_time = between(1, 5)
    username = None
    password = "LocustTest99!@"
    csrf_token = ""
    room_id = None

    def on_start(self):
        """Register and login on spawn."""
        self._register()
        self._login()

    def _get_csrf(self):
        with self.client.get("/api/authentication/csrf-token", catch_response=True) as resp:
            if resp.status_code == 200:
                self.csrf_token = resp.json().get("csrf_token", "")
            else:
                resp.failure(f"CSRF failed: {resp.status_code}")

    def _register(self):
        tag = _random_str(8)
        self.username = f"locust_{tag}"
        payload = {
            "username": self.username,
            "password": self.password,
            "phone": f"+7900{_random_digits(7)}",
            "x25519_public_key": secrets.token_hex(32),
            "display_name": f"Locust {tag}",
        }
        with self.client.post(
            "/api/authentication/register",
            json=payload,
            name="/api/authentication/register",
            catch_response=True,
        ) as resp:
            if resp.status_code == 201:
                resp.success()
            else:
                resp.failure(f"Register: {resp.status_code}")

    def _login(self):
        self._get_csrf()
        payload = {
            "phone_or_username": self.username,
            "password": self.password,
        }
        with self.client.post(
            "/api/authentication/login",
            json=payload,
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/authentication/login",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                resp.success()
                self._get_csrf()
            else:
                resp.failure(f"Login: {resp.status_code}")

    @task(5)
    def health_check(self):
        self.client.get("/health", name="/health")

    @task(3)
    def list_rooms(self):
        self.client.get(
            "/api/rooms/my",
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/rooms/my",
        )

    @task(2)
    def public_rooms(self):
        self.client.get("/api/rooms/public", name="/api/rooms/public")

    @task(2)
    def get_profile(self):
        self.client.get(
            "/api/authentication/me",
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/authentication/me",
        )

    @task(1)
    def create_room(self):
        payload = {
            "name": f"locust_room_{_random_str(6)}",
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }
        with self.client.post(
            "/api/rooms",
            json=payload,
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/rooms [create]",
            catch_response=True,
        ) as resp:
            if resp.status_code in (200, 201):
                data = resp.json()
                self.room_id = data.get("id") or (data.get("room", {}) or {}).get("id")
                resp.success()
            else:
                resp.failure(f"Create room: {resp.status_code}")

    @task(3)
    def room_details(self):
        if not self.room_id:
            return
        self.client.get(
            f"/api/rooms/{self.room_id}",
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/rooms/{id}",
        )

    @task(2)
    def room_members(self):
        if not self.room_id:
            return
        self.client.get(
            f"/api/rooms/{self.room_id}/members",
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/rooms/{id}/members",
        )

    @task(1)
    def peers_status(self):
        self.client.get("/api/peers/status", name="/api/peers/status")

    @task(1)
    def search_users(self):
        self.client.get(
            f"/api/users/search?q={_random_str(3)}",
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/users/search",
        )

    @task(1)
    def contacts_list(self):
        self.client.get(
            "/api/contacts",
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/contacts",
        )

    @task(1)
    def saved_list(self):
        self.client.get(
            "/api/saved",
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/saved",
        )

    @task(1)
    def statuses_list(self):
        self.client.get(
            "/api/statuses",
            headers={"X-CSRF-Token": self.csrf_token},
            name="/api/statuses",
        )
