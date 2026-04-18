"""Vortex Controller — discovery/registry service for Vortex nodes.

This is the "control plane" service. It does NOT handle messaging traffic —
only node discovery, verification, and signed entry URL distribution.

Architecture:
    - Nodes register here (with ed25519 signature proving pubkey ownership)
    - Clients fetch random approved nodes to connect to
    - Controller publishes a signed list of entry URLs (bootstrap endpoints)

See README.md for deployment and protocol details.
"""

VERSION = "0.1.0"
