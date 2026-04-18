# Vortex Controller — Production Deployment

This guide covers how to run the controller so it's reachable even under
aggressive censorship: direct HTTPS + Tor hidden service + IPFS mirror +
Solana Name Service record, all verified by clients against the same
Ed25519 pubkey.

Each channel is independent. Operators who don't need all of them can
deploy just the direct HTTPS flavour and add more later without client
changes.

---

## 1. Direct HTTPS (always required)

### 1.1 Run the controller

```bash
# PostgreSQL is strongly recommended; SQLite is a dev fallback.
export DATABASE_URL="postgresql://vortex:pw@localhost:5432/vortex_controller"
export ENTRY_URLS="wss://node-a.example:9000,wss://node-b.example:9000"

cd vortex_controller
pip install -r requirements.txt
python -m vortex_controller.main
```

Capture the controller pubkey from the log:

```
INFO vortex_controller: Controller pubkey: fe9323d09e8fda9f...
```

Pin this pubkey in client releases. **Every** other channel
re-advertises the same pubkey — if a channel shows a different one, the
client rejects it.

### 1.2 Put it behind Nginx + Let's Encrypt

```nginx
server {
    listen 443 ssl http2;
    server_name vortexx.sol vortexx.example;

    ssl_certificate     /etc/letsencrypt/live/vortexx.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vortexx.example/privkey.pem;

    # Needed so clients can do HEAD probes of entry URLs from the browser.
    add_header Access-Control-Allow-Origin "*";
    add_header Access-Control-Allow-Methods "GET, POST, HEAD, OPTIONS";

    location / {
        proxy_pass         http://127.0.0.1:8800;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

---

## 2. Tor hidden service mirror

### 2.1 Install Tor

Debian/Ubuntu: `sudo apt install tor`, then start it (``systemctl start tor``).

### 2.2 Configure the hidden service

Add to ``/etc/tor/torrc``:

```
HiddenServiceDir /var/lib/tor/vortex_controller/
HiddenServicePort 80 127.0.0.1:8800
```

Restart Tor. Read the generated ``.onion``:

```bash
sudo cat /var/lib/tor/vortex_controller/hostname
# abcdef123…xyz.onion
```

### 2.3 Add it as a mirror

Set the env var for the controller process:

```bash
MIRROR_URLS="http://abcdef123…xyz.onion"
```

Restart the controller. The website's "If this site is blocked" card
will show the onion URL with a signed signature. Clients with Tor
proxies will prefer it when the direct channel is blocked.

### 2.4 Health checking

The controller tries to probe ``.onion`` URLs only when a SOCKS proxy is
configured:

```bash
TOR_SOCKS=127.0.0.1:9050
```

Without that, onion mirrors appear in the list but with a "no tor proxy
configured" note.

---

## 3. IPFS mirror (static bundle)

The controller's website is entirely static, so we can pin it to IPFS
and clients can fetch it through any gateway if DNS is blocked.

### 3.1 Pin with a local kubo daemon

```bash
# Start kubo
ipfs daemon

# Publish the web bundle:
python -m vortex_controller.ipfs_publish

# Output includes:
#   Root CID:  bafybeigdyr…
#   Gateway URLs (try any):
#     https://ipfs.io/ipfs/bafybeigdyr…/
```

### 3.2 Pin with Pinata / Web3.Storage

```bash
IPFS_API=https://api.pinata.cloud \
IPFS_AUTH="Bearer <jwt>" \
python -m vortex_controller.ipfs_publish
```

Any IPFS-compatible API works — the script uses the standard
``/api/v0/add`` endpoint.

### 3.3 Add as a mirror

```bash
MIRROR_URLS="http://abcdef123…xyz.onion,ipfs://bafybeigdyr…"
```

The controller's health checker auto-probes IPFS mirrors via
``ipfs.io/ipfs/<cid>/`` so broken pins turn the status dot red on the
site.

### 3.4 DNSLink for a stable address

Point your domain's ``_dnslink`` TXT record at the CID:

```
_dnslink.vortexx.sol  TXT  "dnslink=/ipfs/bafybeigdyr…"
```

Clients that resolve ``vortexx.sol`` via SNS get the current CID
automatically on every update — you only have to change the TXT record
when you republish.

---

## 4. Solana Name Service (``.sol``)

This is entirely operator-side — the client reads SNS through the
Bonfida gateway (``app/peer/sns_resolver.py``) and doesn't need any
on-chain writes.

### 4.1 Register the domain

Buy ``vortexx.sol`` via https://sns.id or the Bonfida app. You'll need
a Solana wallet with ~0.02 SOL.

### 4.2 Set the records

From the SNS dashboard, add two records to the domain:

| Record | Value |
|--------|-------|
| ``URL``  | ``https://vortexx.example`` (your direct HTTPS URL) |
| ``TXT``  | ``pubkey=<controller hex>;mirrors=ipfs://bafy…,http://xyz.onion`` |

The client-side resolver in Vortex reads both and:
  - Uses ``URL`` to find the controller
  - Checks that the response's pubkey matches the ``pubkey`` in TXT
  - Falls back to any of the ``mirrors`` if the direct URL is blocked

### 4.3 What about propagation?

SNS is on-chain — writes are global in < 1 second. No DNS propagation
delay.

---

## 5. Putting it all together

A fully-channelled deployment ends up looking like this:

```
vortexx.sol  SNS   URL = https://vortexx.example
                  TXT = pubkey=fe9323…;mirrors=ipfs://bafy…,http://xyz.onion
                       |
                       ├──► Direct HTTPS      ← primary, fastest
                       ├──► .onion            ← censorship-resistant
                       └──► IPFS (DNSLink)    ← static content only
```

All channels serve the same signed ``/v1/entries`` and
``/v1/nodes/random``. A client that verifies the Ed25519 signature
against the pinned pubkey doesn't care which channel delivered the
bytes — if the signature checks out, the content is authentic.

---

## 6. Operational checklist

- [ ] Backup ``keys/controller.key`` (losing it = can't issue new signed
      responses; clients reject anything signed by a new key).
- [ ] Rotate ``DATABASE_URL`` password regularly.
- [ ] Monitor ``/v1/health`` (``stats.online`` should track expected node count).
- [ ] Set ``AUTO_APPROVE=false`` once your network is stable — review new
      node registrations manually.
- [ ] Rebuild IPFS pin whenever ``vortex_controller/web/`` changes;
      update the ``_dnslink`` TXT so the stable address points at the new CID.
- [ ] Re-run ``python -m vortex_controller.ipfs_publish`` after each
      controller release so the static bundle mirror is current.
