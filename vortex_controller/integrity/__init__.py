"""Code integrity attestation for the controller.

Proves the running code matches a signed release manifest. Attacker cannot
silently modify a file — the manifest signature breaks, and /v1/integrity
reports the mismatch to every client.

Flow
----
1. Release-time: ``python -m vortex_controller.integrity.sign_tool`` walks
   the source tree, computes SHA256 of every file, signs the result with an
   Ed25519 release key, writes ``INTEGRITY.sig.json``.
2. Startup: ``verify_at_startup()`` loads that file, validates the signature
   against the pinned release pubkey, recomputes hashes, and returns a dict.
3. Runtime: ``GET /v1/integrity`` echoes that dict so clients can see
   ``status == "verified"`` before trusting anything else.

A mismatch does NOT silently pass — both the server log and the website's
fingerprint card render a visible warning.
"""
VERSION = "0.1.0"
