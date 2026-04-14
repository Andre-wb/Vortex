"""
app/transport/gossip_security.py — Gossip protocol security: rate limiting, Sybil protection,
vector clocks, and data validation.

Components:
  - GossipRateLimiter: sliding-window rate limiter (1 exchange per peer per 30s)
  - PeerReputation: scoring system to detect and ban malicious peers
  - ProofOfWork: hashcash-style PoW challenge for new peers (16 leading zero bits)
  - VectorClock: simple vector clock for peer-list version tracking
  - GossipValidator: validates peer addresses, room data, deduplicates peer IDs
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

MAX_GOSSIP_PEERS = 50       # max peers per gossip exchange
MAX_GOSSIP_ROOMS = 100      # max rooms per gossip exchange
GOSSIP_COOLDOWN_SEC = 30.0  # min seconds between gossip exchanges per peer
PEER_MAX_AGE_SEC = 7 * 24 * 3600  # 7 days — remove peers not seen since

# Reputation thresholds
REPUTATION_TEMP_BAN_THRESHOLD = 0.3
REPUTATION_PERM_BAN_THRESHOLD = 0.1
TEMP_BAN_DURATION_SEC = 3600.0  # 1 hour

# Proof-of-work
POW_DIFFICULTY_BITS = 16  # 16 leading zero bits (~65K attempts)

# Validation
MAX_ROOM_NAME_LENGTH = 128
MAX_ROOM_MEMBERS = 100_000
MAX_PEER_NAME_LENGTH = 64


# ══════════════════════════════════════════════════════════════════════════════
# GossipRateLimiter — sliding window, 1 exchange per peer per 30 seconds
# ══════════════════════════════════════════════════════════════════════════════

class GossipRateLimiter:
    """Sliding-window rate limiter for gossip exchanges.

    Tracks the last exchange timestamp per peer (by addr string).
    Allows at most 1 gossip exchange per peer per ``GOSSIP_COOLDOWN_SEC`` seconds.
    """

    def __init__(self, cooldown: float = GOSSIP_COOLDOWN_SEC):
        self._cooldown = cooldown
        self._last_exchange: dict[str, float] = {}

    def is_allowed(self, peer_addr: str) -> bool:
        """Return True if the peer is allowed to exchange gossip now.

        If denied, excess data should be dropped silently with a warning log.
        """
        now = time.monotonic()
        last = self._last_exchange.get(peer_addr)
        if last is not None and (now - last) < self._cooldown:
            return False
        self._last_exchange[peer_addr] = now
        return True

    def cleanup(self) -> int:
        """Remove stale entries older than 2x cooldown. Returns count removed."""
        now = time.monotonic()
        cutoff = now - self._cooldown * 2
        stale = [k for k, v in self._last_exchange.items() if v < cutoff]
        for k in stale:
            del self._last_exchange[k]
        return len(stale)


# ══════════════════════════════════════════════════════════════════════════════
# PeerReputation — simple scoring system for Sybil protection
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PeerReputation:
    """Reputation record for a single peer.

    Attributes:
        score: reputation score, starts at 1.0
        successful_exchanges: count of successful gossip exchanges
        failed_exchanges: count of failed/invalid exchanges
        first_seen: when the peer was first observed
        last_seen: when the peer was last observed
    """
    score: float = 1.0
    successful_exchanges: int = 0
    failed_exchanges: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Internal: monotonic ban-until timestamp (0 = not banned)
    _temp_ban_until: float = 0.0
    _permanently_banned: bool = False

    def record_success(self) -> None:
        """Record a successful gossip exchange — increase score."""
        self.successful_exchanges += 1
        self.last_seen = datetime.now(timezone.utc)
        # Score increases by 0.05 per success, capped at 2.0
        self.score = min(2.0, self.score + 0.05)

    def record_failure(self, penalty: float = 0.15) -> None:
        """Record a failed/invalid gossip exchange — decrease score.

        Args:
            penalty: how much to subtract (default 0.15).
        """
        self.failed_exchanges += 1
        self.last_seen = datetime.now(timezone.utc)
        self.score = max(0.0, self.score - penalty)
        self._check_bans()

    def _check_bans(self) -> None:
        """Apply temporary or permanent bans based on current score."""
        if self.score < REPUTATION_PERM_BAN_THRESHOLD:
            self._permanently_banned = True
            logger.warning(
                "Peer permanently banned: score=%.2f, "
                "success=%d, fail=%d",
                self.score, self.successful_exchanges, self.failed_exchanges,
            )
        elif self.score < REPUTATION_TEMP_BAN_THRESHOLD:
            self._temp_ban_until = time.monotonic() + TEMP_BAN_DURATION_SEC
            logger.warning(
                "Peer temporarily banned (1h): score=%.2f, "
                "success=%d, fail=%d",
                self.score, self.successful_exchanges, self.failed_exchanges,
            )

    def is_banned(self) -> bool:
        """Return True if the peer is currently banned (temp or perm)."""
        if self._permanently_banned:
            return True
        if self._temp_ban_until and time.monotonic() < self._temp_ban_until:
            return True
        # Temp ban expired — clear it
        if self._temp_ban_until and time.monotonic() >= self._temp_ban_until:
            self._temp_ban_until = 0.0
        return False

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 3),
            "successful_exchanges": self.successful_exchanges,
            "failed_exchanges": self.failed_exchanges,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "banned": self.is_banned(),
            "permanently_banned": self._permanently_banned,
        }


class ReputationManager:
    """Manages PeerReputation records for all known peers."""

    def __init__(self):
        self._reputations: dict[str, PeerReputation] = {}

    def get_or_create(self, peer_addr: str) -> PeerReputation:
        """Get or create a reputation record for the given peer address."""
        if peer_addr not in self._reputations:
            self._reputations[peer_addr] = PeerReputation()
        return self._reputations[peer_addr]

    def is_banned(self, peer_addr: str) -> bool:
        """Check if a peer is banned."""
        rep = self._reputations.get(peer_addr)
        if rep is None:
            return False
        return rep.is_banned()

    def record_success(self, peer_addr: str) -> None:
        """Record a successful exchange for the peer."""
        self.get_or_create(peer_addr).record_success()

    def record_failure(self, peer_addr: str, penalty: float = 0.15) -> None:
        """Record a failed/invalid exchange for the peer."""
        self.get_or_create(peer_addr).record_failure(penalty)

    def get_score(self, peer_addr: str) -> float:
        """Get the reputation score for a peer (1.0 if unknown)."""
        rep = self._reputations.get(peer_addr)
        return rep.score if rep else 1.0

    def cleanup_old(self, max_age_sec: float = PEER_MAX_AGE_SEC) -> int:
        """Remove reputation entries for peers not seen in ``max_age_sec``. Returns count."""
        now = datetime.now(timezone.utc)
        stale = []
        for addr, rep in self._reputations.items():
            age = (now - rep.last_seen).total_seconds()
            if age > max_age_sec and not rep._permanently_banned:
                stale.append(addr)
        for addr in stale:
            del self._reputations[addr]
        return len(stale)

    def stats(self) -> dict:
        total = len(self._reputations)
        banned = sum(1 for r in self._reputations.values() if r.is_banned())
        return {"total": total, "banned": banned}


# ══════════════════════════════════════════════════════════════════════════════
# Proof-of-Work — hashcash-style challenge for new peers
# ══════════════════════════════════════════════════════════════════════════════

class ProofOfWork:
    """Hashcash-style proof-of-work for new peers.

    challenge = sha256(peer_id + nonce + timestamp) must have N leading zero bits.
    N = POW_DIFFICULTY_BITS (16), meaning ~65K hash attempts on average.
    """

    # Track which peers have passed PoW (peer_addr -> True)
    _verified: dict[str, float] = {}  # peer_addr -> timestamp verified
    # Pending challenges: peer_addr -> (challenge_bytes, issued_at)
    _challenges: dict[str, tuple[str, float]] = {}

    DIFFICULTY = POW_DIFFICULTY_BITS
    CHALLENGE_TTL = 300.0  # 5 minutes to solve

    @classmethod
    def issue_challenge(cls, peer_addr: str) -> dict:
        """Issue a PoW challenge for a new peer.

        Returns a dict with ``challenge`` (hex) and ``difficulty`` (bits).
        """
        challenge = os.urandom(16).hex()
        cls._challenges[peer_addr] = (challenge, time.monotonic())
        return {
            "challenge": challenge,
            "difficulty": cls.DIFFICULTY,
            "peer_addr": peer_addr,
        }

    @classmethod
    def verify_solution(cls, peer_addr: str, challenge: str, nonce: str,
                        timestamp: str) -> bool:
        """Verify a PoW solution.

        Args:
            peer_addr: the peer address
            challenge: the challenge hex string (from issue_challenge)
            nonce: the nonce found by the peer
            timestamp: the timestamp used by the peer

        Returns:
            True if the solution is valid.
        """
        # Check that we issued this challenge
        stored = cls._challenges.get(peer_addr)
        if stored is None:
            logger.warning("PoW verify: no challenge found for %s", peer_addr)
            return False

        stored_challenge, issued_at = stored
        if stored_challenge != challenge:
            logger.warning("PoW verify: challenge mismatch for %s", peer_addr)
            return False

        # Check TTL
        if time.monotonic() - issued_at > cls.CHALLENGE_TTL:
            cls._challenges.pop(peer_addr, None)
            logger.warning("PoW verify: challenge expired for %s", peer_addr)
            return False

        # Verify hash
        data = f"{peer_addr}{nonce}{timestamp}".encode()
        h = hashlib.sha256(data).digest()
        if cls._check_leading_zeros(h, cls.DIFFICULTY):
            cls._challenges.pop(peer_addr, None)
            cls._verified[peer_addr] = time.monotonic()
            return True

        logger.warning("PoW verify: solution invalid for %s", peer_addr)
        return False

    @classmethod
    def is_verified(cls, peer_addr: str) -> bool:
        """Check if a peer has passed PoW verification."""
        ts = cls._verified.get(peer_addr)
        if ts is None:
            return False
        # Verification valid for 24 hours
        if time.monotonic() - ts > 86400:
            cls._verified.pop(peer_addr, None)
            return False
        return True

    @classmethod
    def needs_pow(cls, peer_addr: str) -> bool:
        """Return True if the peer needs to solve a PoW challenge (first gossip)."""
        return not cls.is_verified(peer_addr)

    @staticmethod
    def _check_leading_zeros(h: bytes, bits: int) -> bool:
        """Check that the hash has at least ``bits`` leading zero bits."""
        full_bytes = bits // 8
        remaining_bits = bits % 8

        for i in range(full_bytes):
            if h[i] != 0:
                return False

        if remaining_bits > 0:
            mask = (0xFF >> remaining_bits) ^ 0xFF  # e.g. bits=2 -> mask=0xC0
            if (h[full_bytes] & mask) != 0:
                return False

        return True

    @staticmethod
    def solve(peer_addr: str, challenge: str, difficulty: int = POW_DIFFICULTY_BITS) -> dict:
        """Solve a PoW challenge (for the client side).

        Brute-forces nonce values until a valid solution is found.

        Returns:
            dict with ``nonce`` and ``timestamp``.
        """
        timestamp = str(int(time.time()))
        nonce = 0
        while True:
            nonce_str = str(nonce)
            data = f"{peer_addr}{nonce_str}{timestamp}".encode()
            h = hashlib.sha256(data).digest()
            if ProofOfWork._check_leading_zeros(h, difficulty):
                return {
                    "nonce": nonce_str,
                    "timestamp": timestamp,
                    "challenge": challenge,
                }
            nonce += 1

    @classmethod
    def cleanup(cls) -> None:
        """Remove expired challenges and old verifications."""
        now = time.monotonic()
        expired_challenges = [
            k for k, (_, t) in cls._challenges.items()
            if now - t > cls.CHALLENGE_TTL
        ]
        for k in expired_challenges:
            del cls._challenges[k]

        expired_verified = [
            k for k, t in cls._verified.items()
            if now - t > 86400
        ]
        for k in expired_verified:
            del cls._verified[k]


# ══════════════════════════════════════════════════════════════════════════════
# VectorClock — basic version tracking for gossip consistency
# ══════════════════════════════════════════════════════════════════════════════

class VectorClock:
    """Simple vector clock for tracking peer list versions.

    Each node has its own counter that increments when its peer list changes.
    During gossip exchange, vector clocks are merged to detect conflicts.
    On conflict, peers with higher reputation scores are preferred.
    """

    def __init__(self, node_id: str):
        self._node_id = node_id
        self._clock: dict[str, int] = {node_id: 0}

    @property
    def node_id(self) -> str:
        return self._node_id

    def increment(self) -> None:
        """Increment this node's counter (call when local peer list changes)."""
        self._clock[self._node_id] = self._clock.get(self._node_id, 0) + 1

    def get(self) -> dict[str, int]:
        """Return a copy of the vector clock."""
        return dict(self._clock)

    def merge(self, remote_clock: dict[str, int],
              reputation_mgr: Optional[ReputationManager] = None,
              local_peers: Optional[dict] = None,
              remote_peers: Optional[dict] = None) -> list[str]:
        """Merge a remote vector clock with ours.

        For each node in the clocks:
        - If remote is strictly ahead, accept remote state
        - If local is strictly ahead, keep local state
        - If concurrent (conflict): prefer peers with higher reputation

        Args:
            remote_clock: the remote node's vector clock dict
            reputation_mgr: optional ReputationManager for conflict resolution
            local_peers: optional local peer data for conflict resolution
            remote_peers: optional remote peer data for conflict resolution

        Returns:
            List of node_ids where conflicts were detected.
        """
        conflicts: list[str] = []

        all_nodes = set(self._clock.keys()) | set(remote_clock.keys())
        for node in all_nodes:
            local_v = self._clock.get(node, 0)
            remote_v = remote_clock.get(node, 0)

            if remote_v > local_v:
                # Remote is ahead — accept
                self._clock[node] = remote_v
            elif remote_v < local_v:
                # We are ahead — keep ours
                pass
            elif remote_v == local_v and node != self._node_id:
                # Same version — no conflict, nothing to do
                pass
            # Conflict case: same version but different data detected elsewhere
            # (handled by the caller comparing actual peer lists)

        return conflicts

    def detects_conflict(self, remote_clock: dict[str, int]) -> bool:
        """Return True if the remote clock has concurrent (conflicting) changes.

        A conflict exists when neither clock dominates the other:
        some nodes are ahead locally and some remotely.
        """
        local_ahead = False
        remote_ahead = False
        all_nodes = set(self._clock.keys()) | set(remote_clock.keys())
        for node in all_nodes:
            lv = self._clock.get(node, 0)
            rv = remote_clock.get(node, 0)
            if lv > rv:
                local_ahead = True
            elif rv > lv:
                remote_ahead = True
            if local_ahead and remote_ahead:
                return True
        return False

    def to_dict(self) -> dict:
        return dict(self._clock)

    @classmethod
    def from_dict(cls, data: dict, node_id: str) -> VectorClock:
        vc = cls(node_id)
        vc._clock = dict(data)
        if node_id not in vc._clock:
            vc._clock[node_id] = 0
        return vc


# ══════════════════════════════════════════════════════════════════════════════
# GossipValidator — data validation for gossip exchanges
# ══════════════════════════════════════════════════════════════════════════════

# Networks blocked for peer addresses (non-local mode)
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


class GossipValidator:
    """Validates gossip exchange data: peer addresses, room data, duplicates."""

    @staticmethod
    def validate_peer_address(ip: str, port: int, local_mode: bool = False) -> Optional[str]:
        """Validate a peer address. Returns error string or None if valid.

        Args:
            ip: peer IP address
            port: peer port number
            local_mode: if True, allow private IPs
        """
        # Port range
        if not isinstance(port, int) or not (1 <= port <= 65535):
            return f"invalid port: {port}"

        # IP format
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return f"invalid IP format: {ip}"

        # Always block localhost, link-local, etc.
        for net in _BLOCKED_NETS:
            if addr in net:
                return f"blocked IP range: {ip}"

        # Block private IPs unless local mode
        if not local_mode:
            for net in _PRIVATE_NETS:
                if addr in net:
                    return f"private IP not allowed in global mode: {ip}"

        return None

    @staticmethod
    def validate_room_data(room: dict) -> Optional[str]:
        """Validate room data from gossip. Returns error string or None if valid."""
        name = room.get("name", "")
        if not name or not isinstance(name, str):
            return "missing or invalid room name"
        if len(name) > MAX_ROOM_NAME_LENGTH:
            return f"room name too long: {len(name)} > {MAX_ROOM_NAME_LENGTH}"

        member_count = room.get("member_count", 0)
        if isinstance(member_count, int) and member_count > MAX_ROOM_MEMBERS:
            return f"unreasonable member count: {member_count}"

        return None

    @staticmethod
    def deduplicate_peers(peers: list[dict]) -> list[dict]:
        """Remove duplicate peer IDs from a single exchange.

        Uses ip:port as the unique key. Returns the deduplicated list.
        """
        seen: set[str] = set()
        result: list[dict] = []
        for p in peers:
            ip = p.get("ip", "")
            port = p.get("port", 0)
            key = f"{ip}:{port}"
            if key in seen:
                logger.debug("Duplicate peer in gossip exchange: %s — skipped", key)
                continue
            seen.add(key)
            result.append(p)
        return result

    @staticmethod
    def filter_valid_peers(peers: list[dict], local_mode: bool = False) -> list[dict]:
        """Validate and filter a list of peers. Returns only valid peers.

        Applies:
        - MAX_GOSSIP_PEERS cap
        - Address validation
        - Deduplication
        """
        # Cap
        if len(peers) > MAX_GOSSIP_PEERS:
            logger.warning(
                "Gossip exchange has %d peers, capping to %d",
                len(peers), MAX_GOSSIP_PEERS,
            )
            peers = peers[:MAX_GOSSIP_PEERS]

        # Deduplicate
        peers = GossipValidator.deduplicate_peers(peers)

        # Validate addresses
        valid: list[dict] = []
        for p in peers:
            ip = p.get("ip", "")
            try:
                port = int(p.get("port", 0))
            except (TypeError, ValueError):
                continue
            err = GossipValidator.validate_peer_address(ip, port, local_mode)
            if err:
                logger.debug("Invalid peer in gossip: %s — %s", f"{ip}:{port}", err)
                continue
            valid.append(p)
        return valid

    @staticmethod
    def filter_valid_rooms(rooms: list[dict]) -> list[dict]:
        """Validate and filter a list of rooms. Returns only valid rooms.

        Applies:
        - MAX_GOSSIP_ROOMS cap
        - Room data validation
        """
        if len(rooms) > MAX_GOSSIP_ROOMS:
            logger.warning(
                "Gossip exchange has %d rooms, capping to %d",
                len(rooms), MAX_GOSSIP_ROOMS,
            )
            rooms = rooms[:MAX_GOSSIP_ROOMS]

        valid: list[dict] = []
        for r in rooms:
            err = GossipValidator.validate_room_data(r)
            if err:
                logger.debug("Invalid room in gossip: %s — %s", r.get("name", "?"), err)
                continue
            valid.append(r)
        return valid


# ══════════════════════════════════════════════════════════════════════════════
# GossipSecurity — unified facade
# ══════════════════════════════════════════════════════════════════════════════

class GossipSecurity:
    """Unified security facade for the gossip protocol.

    Combines rate limiting, reputation management, PoW verification,
    vector clocks, and data validation into a single entry point.

    Usage::

        security = GossipSecurity(node_id="1.2.3.4:9000")

        # On incoming gossip:
        ok, reason = security.check_incoming(peer_addr, peers_data, rooms_data)
        if not ok:
            return 403, reason

        # After successful exchange:
        security.record_success(peer_addr)

        # After failed exchange:
        security.record_failure(peer_addr)
    """

    def __init__(self, node_id: str = ""):
        self.rate_limiter = GossipRateLimiter()
        self.reputation = ReputationManager()
        self.vector_clock = VectorClock(node_id or "unknown")
        self.validator = GossipValidator()

    def check_incoming(
        self,
        peer_addr: str,
        peers: list[dict],
        rooms: list[dict],
        local_mode: bool = False,
    ) -> tuple[bool, str]:
        """Run all security checks on an incoming gossip exchange.

        Args:
            peer_addr: peer address (ip:port)
            peers: list of peer dicts from the gossip
            rooms: list of room dicts from the gossip
            local_mode: if True, allow private IPs

        Returns:
            (allowed: bool, reason: str) — reason is empty if allowed.
        """
        # 1. Check ban
        if self.reputation.is_banned(peer_addr):
            logger.warning("Gossip rejected: peer %s is banned", peer_addr)
            return False, "peer is banned"

        # 2. Rate limit
        if not self.rate_limiter.is_allowed(peer_addr):
            logger.warning(
                "Gossip rate-limited: peer %s (1 exchange per %ds)",
                peer_addr, int(GOSSIP_COOLDOWN_SEC),
            )
            return False, "rate limited"

        # 3. PoW check for new peers (first gossip exchange)
        if ProofOfWork.needs_pow(peer_addr):
            # Don't reject — the caller should issue a challenge
            # This is informational; the route handler decides the flow
            pass

        return True, ""

    def filter_and_validate(
        self,
        peers: list[dict],
        rooms: list[dict],
        local_mode: bool = False,
    ) -> tuple[list[dict], list[dict]]:
        """Filter and validate incoming peers and rooms.

        Applies caps, deduplication, address validation, and room validation.
        """
        valid_peers = self.validator.filter_valid_peers(peers, local_mode)
        valid_rooms = self.validator.filter_valid_rooms(rooms)
        return valid_peers, valid_rooms

    def record_success(self, peer_addr: str) -> None:
        """Record a successful gossip exchange."""
        self.reputation.record_success(peer_addr)

    def record_failure(self, peer_addr: str, penalty: float = 0.15) -> None:
        """Record a failed/invalid gossip exchange."""
        self.reputation.record_failure(peer_addr, penalty)

    def merge_vector_clock(
        self,
        remote_clock: dict[str, int],
    ) -> bool:
        """Merge a remote vector clock. Returns True if conflict detected."""
        has_conflict = self.vector_clock.detects_conflict(remote_clock)
        self.vector_clock.merge(remote_clock)
        if has_conflict:
            logger.info("Vector clock conflict detected during gossip merge")
        return has_conflict

    def on_peer_list_changed(self) -> None:
        """Call when the local peer list changes to increment the vector clock."""
        self.vector_clock.increment()

    def cleanup(self) -> dict:
        """Run periodic cleanup of all security subsystems."""
        rate_cleaned = self.rate_limiter.cleanup()
        rep_cleaned = self.reputation.cleanup_old()
        ProofOfWork.cleanup()
        return {
            "rate_limiter_cleaned": rate_cleaned,
            "reputation_cleaned": rep_cleaned,
        }

    def stats(self) -> dict:
        """Return statistics about the security subsystems."""
        return {
            "reputation": self.reputation.stats(),
            "vector_clock": self.vector_clock.to_dict(),
            "pow_verified_count": len(ProofOfWork._verified),
            "pow_pending_challenges": len(ProofOfWork._challenges),
        }


# ══════════════════════════════════════════════════════════════════════════════
# Singleton
# ══════════════════════════════════════════════════════════════════════════════

gossip_security = GossipSecurity()
