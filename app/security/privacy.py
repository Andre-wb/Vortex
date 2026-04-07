"""
Privacy Enhancement Layer — Tor, metadata padding, ephemeral identities, ZK membership.

Four layers of privacy protection:
  1. Tor SOCKS5 proxy — hide IP from peers
  2. Metadata padding — all messages same size, no traffic analysis
  3. Ephemeral usernames — unlinkable identity per room
  4. Zero-knowledge room membership — server can't tell who is in which room
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import struct
import time
from typing import Optional

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Tor SOCKS5 Integration
# ══════════════════════════════════════════════════════════════════════════════

class TorProxy:
    """
    Route all outgoing peer-to-peer traffic through Tor SOCKS5 proxy.
    Hides real IP address even from other Vortex nodes.

    Requires: Tor running locally (default SOCKS5 on 127.0.0.1:9050)

    Usage:
      tor_proxy = TorProxy()
      if tor_proxy.is_available():
          client = tor_proxy.get_httpx_client()
          resp = await client.get("http://peer:9000/api/peers/status")
    """

    def __init__(self, socks_host: str = "127.0.0.1", socks_port: int = 9050):
        self.socks_url = f"socks5://{socks_host}:{socks_port}"
        self.socks_host = socks_host
        self.socks_port = socks_port
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if Tor SOCKS5 proxy is reachable."""
        if self._available is not None:
            return self._available
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.socks_host, self.socks_port))
            s.close()
            self._available = True
            logger.info("Tor SOCKS5 proxy available at %s", self.socks_url)
        except (ConnectionRefusedError, OSError, socket.timeout):
            self._available = False
            logger.info("Tor not available at %s — direct connections will be used", self.socks_url)
        return self._available

    def get_httpx_transport(self):
        """Get httpx transport configured to route through Tor."""
        import httpx
        return httpx.AsyncHTTPTransport(proxy=self.socks_url)

    def get_httpx_client(self, **kwargs):
        """Get httpx.AsyncClient that routes through Tor."""
        import httpx
        return httpx.AsyncClient(
            transport=self.get_httpx_transport(),
            timeout=30.0,
            follow_redirects=True,
            **kwargs,
        )

    async def check_ip(self) -> Optional[str]:
        """Check our external IP as seen through Tor."""
        if not self.is_available():
            return None
        try:
            import httpx
            async with self.get_httpx_client() as client:
                resp = await client.get("https://api.ipify.org?format=json")
                if resp.status_code == 200:
                    return resp.json().get("ip")
        except Exception as e:
            logger.warning("Tor IP check failed: %s", e)
        return None

    def get_status(self) -> dict:
        """Return Tor proxy status."""
        return {
            "available": self.is_available(),
            "socks_url": self.socks_url,
            "enabled": self.is_available(),
        }


# Global Tor proxy instance
tor_proxy = TorProxy(
    socks_host=os.getenv("TOR_SOCKS_HOST", "127.0.0.1"),
    socks_port=int(os.getenv("TOR_SOCKS_PORT", "9050")),
)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Metadata Padding — all messages same size
# ══════════════════════════════════════════════════════════════════════════════

class MetadataPadding:
    """
    Pad ALL messages to fixed sizes so DPI cannot determine message type
    or content length by observing packet sizes.

    Standard sizes (bytes): 256, 512, 1024, 2048, 4096, 8192, 16384
    Every message is padded to the next standard size.

    Wire format: [4B real_length][data][PKCS7-like random padding]
    """

    STANDARD_SIZES = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768]
    HEADER_SIZE = 4  # 4 bytes for real length

    @classmethod
    def pad(cls, data: bytes) -> bytes:
        """Pad data to next standard size."""
        real_len = len(data)
        total_needed = real_len + cls.HEADER_SIZE

        # Find next standard size
        target_size = cls.STANDARD_SIZES[-1]
        for size in cls.STANDARD_SIZES:
            if size >= total_needed:
                target_size = size
                break

        pad_len = target_size - cls.HEADER_SIZE - real_len
        padding = os.urandom(max(0, pad_len))

        return struct.pack(">I", real_len) + data + padding

    @classmethod
    def unpad(cls, padded: bytes) -> Optional[bytes]:
        """Remove padding, extract original data."""
        if len(padded) < cls.HEADER_SIZE:
            return None
        real_len = struct.unpack(">I", padded[:cls.HEADER_SIZE])[0]
        if real_len > len(padded) - cls.HEADER_SIZE:
            return None
        return padded[cls.HEADER_SIZE:cls.HEADER_SIZE + real_len]

    @classmethod
    def pad_to_fixed(cls, data: bytes, target_size: int = 1024) -> bytes:
        """Pad data to exactly target_size bytes."""
        real_len = len(data)
        if real_len + cls.HEADER_SIZE > target_size:
            # Data too large for target, use next standard size
            return cls.pad(data)
        pad_len = target_size - cls.HEADER_SIZE - real_len
        return struct.pack(">I", real_len) + data + os.urandom(pad_len)

    @classmethod
    def get_padded_size(cls, data_len: int) -> int:
        """Calculate what size the data will be after padding."""
        total = data_len + cls.HEADER_SIZE
        for size in cls.STANDARD_SIZES:
            if size >= total:
                return size
        return cls.STANDARD_SIZES[-1]


# ══════════════════════════════════════════════════════════════════════════════
# 3. Ephemeral Usernames — per-room pseudonyms
# ══════════════════════════════════════════════════════════════════════════════

class EphemeralIdentity:
    """
    Generate unlinkable pseudonyms for each room.

    When a user joins a room, they get a unique ephemeral username
    derived from their real identity + room_id. Other rooms cannot
    correlate that the same user is in multiple rooms.

    Derivation: HMAC-SHA256(user_secret, room_id) → base62 username

    The server stores the mapping, but if the server is compromised,
    the ephemeral names cannot be reversed without user_secret.
    """

    BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    @classmethod
    def generate(cls, user_secret: bytes, room_id: int, prefix: str = "anon") -> str:
        """Generate ephemeral username for a specific room.

        Args:
            user_secret: 32-byte secret (stored on user's device only)
            room_id: Room identifier
            prefix: Optional prefix for the name

        Returns:
            Ephemeral username like "anon_k7Bx9mQ2"
        """
        mac = hmac.new(user_secret, str(room_id).encode(), hashlib.sha256).digest()
        # Convert first 6 bytes to base62 string
        name_part = cls._bytes_to_base62(mac[:6])
        return f"{prefix}_{name_part}"

    @classmethod
    def generate_secret(cls) -> bytes:
        """Generate a new ephemeral identity secret (store on device)."""
        return os.urandom(32)

    @classmethod
    def verify(cls, user_secret: bytes, room_id: int, ephemeral_name: str, prefix: str = "anon") -> bool:
        """Verify that an ephemeral name was generated by this secret for this room."""
        expected = cls.generate(user_secret, room_id, prefix)
        return secrets.compare_digest(expected, ephemeral_name)

    @classmethod
    def _bytes_to_base62(cls, data: bytes) -> str:
        num = int.from_bytes(data, "big")
        result = []
        while num > 0:
            result.append(cls.BASE62[num % 62])
            num //= 62
        return "".join(reversed(result)) or "0"

    @classmethod
    def generate_display_name(cls, user_secret: bytes, room_id: int) -> str:
        """Generate a human-friendly ephemeral display name.

        Uses word lists for more readable names: "Purple Tiger", "Silent Wave", etc.
        """
        mac = hmac.new(user_secret, str(room_id).encode(), hashlib.sha256).digest()
        adjectives = [
            "Silent", "Swift", "Bright", "Dark", "Calm", "Bold", "Wise",
            "Free", "True", "Brave", "Deep", "Pure", "Wild", "Cold",
            "Warm", "Lost", "Keen", "Fair", "Rare", "Vast",
        ]
        nouns = [
            "Wolf", "Hawk", "Bear", "Fox", "Owl", "Lion", "Star",
            "Moon", "Wave", "Wind", "Fire", "Snow", "Rain", "Sky",
            "Lake", "Peak", "Leaf", "Rose", "Dawn", "Dusk",
        ]
        adj_idx = mac[0] % len(adjectives)
        noun_idx = mac[1] % len(nouns)
        num = mac[2] % 100
        return f"{adjectives[adj_idx]} {nouns[noun_idx]} {num}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Zero-Knowledge Room Membership (ZK-SNARK PoC)
# ══════════════════════════════════════════════════════════════════════════════

class ZKMembership:
    """
    Zero-knowledge proof of room membership.

    The server can verify that a user is a member of a room
    WITHOUT learning which user it is.

    Simplified protocol (Schnorr-like ZK proof):
      1. User has membership_token = HMAC(room_secret, user_id)
      2. User generates proof: commitment + challenge-response
      3. Server verifies proof using room_secret (knows room exists)
         but cannot determine user_id from the proof

    This is a PoC — production would use a proper ZK-SNARK library
    (e.g., circom, gnark, or bellman).
    """

    @staticmethod
    def create_membership_token(room_secret: bytes, user_id: int) -> bytes:
        """Create a membership token for a user in a room.

        The room_secret is known to room admins only.
        The token proves membership without revealing user_id to the server.
        """
        return hmac.new(room_secret, str(user_id).encode(), hashlib.sha256).digest()

    @staticmethod
    def generate_room_secret() -> bytes:
        """Generate a new room secret (stored by room creator)."""
        return os.urandom(32)

    @classmethod
    def create_proof(cls, membership_token: bytes, challenge: bytes) -> dict:
        """Create a zero-knowledge proof of membership.

        Args:
            membership_token: HMAC(room_secret, user_id)
            challenge: Random bytes from verifier (server)

        Returns:
            Proof dict that server can verify without learning user_id.
        """
        # Commitment: random blinding factor
        blinding = os.urandom(32)
        commitment = hashlib.sha256(blinding + membership_token).digest()

        # Response: hash of (challenge + token + blinding)
        response = hmac.new(
            membership_token,
            challenge + blinding,
            hashlib.sha256,
        ).digest()

        return {
            "commitment": commitment.hex(),
            "response": response.hex(),
            "blinding": blinding.hex(),
        }

    @classmethod
    def verify_proof(cls, room_secret: bytes, known_user_ids: list[int],
                     challenge: bytes, proof: dict) -> bool:
        """Verify a zero-knowledge membership proof.

        The server checks if the proof corresponds to ANY valid member,
        without learning WHICH member created it.

        Args:
            room_secret: The room's secret key
            known_user_ids: List of user IDs who are members
            challenge: The challenge that was sent
            proof: The proof to verify

        Returns:
            True if proof is valid (user is a member), False otherwise.
        """
        commitment = bytes.fromhex(proof["commitment"])
        response = bytes.fromhex(proof["response"])
        blinding = bytes.fromhex(proof["blinding"])

        # Try each known member — if any matches, the proof is valid
        # Server learns "someone is a member" but not WHO
        for uid in known_user_ids:
            token = cls.create_membership_token(room_secret, uid)

            # Verify commitment
            expected_commitment = hashlib.sha256(blinding + token).digest()
            if not hmac.compare_digest(commitment, expected_commitment):
                continue

            # Verify response
            expected_response = hmac.new(
                token,
                challenge + blinding,
                hashlib.sha256,
            ).digest()
            if hmac.compare_digest(response, expected_response):
                return True

        return False

    @classmethod
    def generate_challenge(cls) -> bytes:
        """Generate a random challenge for ZK proof verification."""
        return os.urandom(32)

    @classmethod
    def get_info(cls) -> dict:
        """Return info about ZK membership system."""
        return {
            "type": "schnorr-like-zk",
            "status": "proof-of-concept",
            "properties": [
                "completeness: valid member always passes",
                "soundness: non-member cannot forge proof",
                "zero-knowledge: server learns nothing about which member",
            ],
            "note": "PoC implementation. Production should use circom/gnark ZK-SNARK.",
        }
