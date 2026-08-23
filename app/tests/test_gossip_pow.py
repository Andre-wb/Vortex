"""Приём решения proof-of-work на /api/federation/gossip/node-joined."""

import secrets

import pytest
from conftest import SyncASGIClient, fed_proof_headers, random_str

from app.federation.trusted_nodes import _gossip_rate_limiter
from app.transport.gossip_security import ProofOfWork


@pytest.fixture
def pow_required():
    saved_verified = dict(ProofOfWork._verified)
    saved_challenges = dict(ProofOfWork._challenges)
    saved_cooldown = _gossip_rate_limiter._cooldown
    ProofOfWork._verified.clear()
    ProofOfWork._challenges.clear()
    _gossip_rate_limiter._cooldown = 0.0
    yield
    ProofOfWork._verified.clear()
    ProofOfWork._verified.update(saved_verified)
    ProofOfWork._challenges.clear()
    ProofOfWork._challenges.update(saved_challenges)
    _gossip_rate_limiter._cooldown = saved_cooldown


def _payload(client: SyncASGIClient) -> dict:
    local_hash = client.get("/api/federation/code-hash", headers=fed_proof_headers()).json()["code_hash"]
    return {
        "node_id": secrets.token_hex(16),
        "url": f"https://pow-{random_str()}.example.com:8443",
        "code_hash": local_hash,
        "version": "1.0.0",
    }


class TestGossipProofOfWork:
    def test_challenge_issued_when_solution_absent(self, client: SyncASGIClient, logged_user: dict, pow_required):
        r = client.post(
            "/api/federation/gossip/node-joined",
            json=_payload(client),
            headers=logged_user["headers"],
        )
        assert r.status_code == 428
        detail = r.json()["error"]
        assert len(detail["challenge"]) == 32
        assert detail["difficulty"] == ProofOfWork.DIFFICULTY
        assert detail["peer_addr"]

    def test_valid_solution_is_accepted(self, client: SyncASGIClient, logged_user: dict, pow_required):
        body = _payload(client)
        first = client.post(
            "/api/federation/gossip/node-joined",
            json=body,
            headers=logged_user["headers"],
        )
        assert first.status_code == 428
        detail = first.json()["error"]

        solution = ProofOfWork.solve(detail["peer_addr"], detail["challenge"])
        body |= {
            "pow_challenge": detail["challenge"],
            "pow_nonce": solution["nonce"],
            "pow_timestamp": solution["timestamp"],
        }
        second = client.post(
            "/api/federation/gossip/node-joined",
            json=body,
            headers=logged_user["headers"],
        )
        assert second.status_code == 200
        assert second.json()["status"] == "added_as_pending"

    def test_wrong_nonce_is_refused_with_a_fresh_challenge(
        self, client: SyncASGIClient, logged_user: dict, pow_required
    ):
        body = _payload(client)
        first = client.post(
            "/api/federation/gossip/node-joined",
            json=body,
            headers=logged_user["headers"],
        )
        assert first.status_code == 428
        challenge = first.json()["error"]["challenge"]

        body |= {"pow_challenge": challenge, "pow_nonce": "0", "pow_timestamp": "1"}
        second = client.post(
            "/api/federation/gossip/node-joined",
            json=body,
            headers=logged_user["headers"],
        )
        assert second.status_code == 428
        assert second.json()["error"]["challenge"] != challenge

    def test_challenge_we_did_not_issue_is_refused(self, client: SyncASGIClient, logged_user: dict, pow_required):
        body = _payload(client)
        first = client.post(
            "/api/federation/gossip/node-joined",
            json=body,
            headers=logged_user["headers"],
        )
        assert first.status_code == 428
        peer_addr = first.json()["error"]["peer_addr"]

        forged = secrets.token_hex(16)
        solution = ProofOfWork.solve(peer_addr, forged)
        body |= {
            "pow_challenge": forged,
            "pow_nonce": solution["nonce"],
            "pow_timestamp": solution["timestamp"],
        }
        second = client.post(
            "/api/federation/gossip/node-joined",
            json=body,
            headers=logged_user["headers"],
        )
        assert second.status_code == 428

    def test_verified_peer_skips_the_challenge(self, client: SyncASGIClient, logged_user: dict, pow_required):
        body = _payload(client)
        first = client.post(
            "/api/federation/gossip/node-joined",
            json=body,
            headers=logged_user["headers"],
        )
        detail = first.json()["error"]
        solution = ProofOfWork.solve(detail["peer_addr"], detail["challenge"])
        client.post(
            "/api/federation/gossip/node-joined",
            json=body | {
                "pow_challenge": detail["challenge"],
                "pow_nonce": solution["nonce"],
                "pow_timestamp": solution["timestamp"],
            },
            headers=logged_user["headers"],
        )

        again = client.post(
            "/api/federation/gossip/node-joined",
            json=_payload(client),
            headers=logged_user["headers"],
        )
        assert again.status_code == 200
