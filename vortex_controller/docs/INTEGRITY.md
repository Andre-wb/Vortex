# Code Integrity Attestation

Every controller release is signed with an Ed25519 key. At startup the
controller:

1. Loads `INTEGRITY.sig.json` from the project root
2. Verifies the Ed25519 signature against the pinned release public key
3. Recomputes SHA-256 of every tracked source file and compares to the manifest
4. Exposes the result at `GET /v1/integrity` for any client to inspect

Verification runs **once at startup** — zero runtime cost per request.

## What's "tracked"

Every `.py`, `.html`, `.css`, `.js`, `.json`, `.md`, `.toml`, `.txt`, `.svg`
under `vortex_controller/`, minus:

- `__pycache__/`, `.venv/`, `target/`, `node_modules/`, `.git/`
- `keys/` (runtime per-deployment keys, not code)
- `controller.db`, `.env`, `controller.key`
- `INTEGRITY.sig.json` itself (excluded from self-signing)

## Commands

### Build + sign (release-time)

```bash
# First run auto-generates keys/release.key (keep this file safe!)
python -m vortex_controller.integrity.sign_tool

# Show the public key to pin in clients:
python -m vortex_controller.integrity.sign_tool --show-pubkey
```

Output: `INTEGRITY.sig.json` at the project root.

### Verify status (any time)

```bash
curl http://localhost:8800/v1/integrity | jq
```

Expected response on a clean build:
```json
{
  "status": "verified",
  "signed_by": "f80c0fc173fac6ca7218a05245df8de97e1ed755853050da873bc1fdddce0198",
  "version": "0.1.0",
  "matched": 156,
  "mismatched": [],
  "missing": [],
  "message": "All 156 files match manifest v0.1.0 (…)"
}
```

Possible `status` values:
- `verified` — signature valid, all files match
- `tampered` — signature valid but some files differ
- `bad_signature` — signature doesn't verify
- `wrong_key` — signed by a key you don't trust
- `no_manifest` — `INTEGRITY.sig.json` missing (dev mode)

### Strict startup

Refuse to boot if integrity fails:
```bash
INTEGRITY_STRICT=true python -m vortex_controller.main
```

By default the controller logs a warning but continues, since operators
running off a local dev checkout may legitimately have no manifest.

## Pinning the release pubkey

Put the upstream pubkey in one of:

1. `VORTEX_OFFICIAL_RELEASE_PUBKEY` build-time constant in
   `vortex_controller/integrity/verify.py` (replace the empty default
   with your real pubkey before tagging a release).
2. `RELEASE_PUBKEY` env var at runtime (operator-managed deployments
   with their own signing key).

If both are unset, any self-signed manifest is accepted as "verified" —
this is useful for dev but should NEVER be the case in production.

## Publishing the pubkey to clients

When a client connects to `vortexx.sol`, it should:

1. Resolve the SNS `TXT` record (Phase 4) — it already contains
   `pubkey=<controller pubkey>`. Add `release_pubkey=<hex>` to the same
   record so clients can cross-check.
2. Call `GET /v1/integrity` and confirm `signed_by == release_pubkey`.
3. If the two match and `status == "verified"`, the code is proven
   authentic and the controller's operational pubkey can be trusted
   for signing further responses.

## Key rotation

If the private release key is lost or compromised:

1. Generate a new key: `python -m vortex_controller.integrity.sign_tool --key keys/release.key.new`
2. Re-sign the tree: move the new key into place, re-run `sign_tool`
3. Update the pinned pubkey in `verify.py` AND the `release_pubkey=` field
   in the SNS `TXT` record
4. Roll out a client update so users who pin the key learn about the change

## Known limitations

- Does **not** protect against an attacker who compromises the running
  server AND swaps the manifest before startup — they can produce a
  matching signature with a key they control, and clients would see
  `signed_by != release_pubkey`. That's detectable but not preventable
  by this scheme alone; it has to be combined with secure boot or
  remote attestation for true TPM-style protection.
- Does **not** cover Python dependencies (`.venv/` is excluded). Use
  `pip install --require-hashes` and a pinned `requirements.txt` for that.
- Does **not** cover the OS, kernel, or the Python interpreter itself.
  Those are the platform operator's responsibility.
