"""
app/security/blockchain_verify.py — Blockchain transaction verification.

Verifies crypto payments by querying public blockchain explorer APIs.
No private keys, no wallets — read-only public data only.

Supported networks:
  - TRON (TRC20 USDT)  → api.trongrid.io        (no API key required)
  - Ethereum (ERC20)   → api.etherscan.io        (optional ETHERSCAN_API_KEY)
  - BSC (BEP20)        → api.bscscan.com         (optional BSCSCAN_API_KEY)
  - TON                → toncenter.com           (no API key required)
  - Bitcoin            → blockstream.info        (no API key required)

Usage:
    result = await verify_transaction(
        tx_hash="abc123...",
        wallet_address="TXyz...",
        expected_amount="5 USDT",
        currency="USDT",
        network="trc20",
    )
    if not result.ok:
        raise HTTPException(402, result.error)
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Confirmation thresholds (blocks) ──────────────────────────────────────────
_CONFIRMATIONS = {
    "trc20": 19,   # TRON: ~19 blocks ≈ 1 min
    "erc20": 12,   # Ethereum: ~12 blocks ≈ 2.5 min
    "bep20": 15,   # BSC: ~15 blocks ≈ 45 sec
    "ton":   1,    # TON: 1 masterchain block is final
    "btc":   3,    # Bitcoin: 3 blocks ≈ 30 min
}

# ── API keys from environment (optional) ──────────────────────────────────────
_ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
_BSCSCAN_KEY   = os.environ.get("BSCSCAN_API_KEY", "")

# ── HTTP timeout ───────────────────────────────────────────────────────────────
_TIMEOUT = 10.0  # seconds


@dataclass
class VerificationResult:
    ok: bool
    error: Optional[str] = None
    confirmations: int = 0
    amount_received: str = ""
    network: str = ""


# ══════════════════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════════════════

async def verify_transaction(
    tx_hash: str,
    wallet_address: str,
    expected_amount: str,   # e.g. "5 USDT" or "0.001 BTC"
    currency: str,          # "USDT" | "TON" | "BTC" | "ETH"
    network: str,           # "trc20" | "erc20" | "bep20" | "ton" | "btc"
) -> VerificationResult:
    """Verify a blockchain transaction.

    Checks:
      1. Transaction exists and is confirmed (network-specific threshold)
      2. Recipient address matches wallet_address
      3. Amount received >= expected_amount (parsed from string)

    Returns VerificationResult with ok=True on success or ok=False + error message.
    """
    tx_hash    = tx_hash.strip()
    network    = network.lower().strip()
    currency   = currency.upper().strip()
    wallet_address = wallet_address.strip()

    if not tx_hash:
        return VerificationResult(ok=False, error="tx_hash is required")

    # Validate tx_hash format
    if not re.match(r"^[0-9a-fA-F]{40,100}$", tx_hash):
        return VerificationResult(ok=False, error="Invalid tx_hash format")

    min_amount = _parse_amount(expected_amount)

    try:
        if network == "trc20":
            return await _verify_tron(tx_hash, wallet_address, min_amount)
        elif network == "erc20":
            return await _verify_evm(tx_hash, wallet_address, min_amount, chain="eth")
        elif network == "bep20":
            return await _verify_evm(tx_hash, wallet_address, min_amount, chain="bsc")
        elif network == "ton":
            return await _verify_ton(tx_hash, wallet_address, min_amount)
        elif network == "btc":
            return await _verify_btc(tx_hash, wallet_address, min_amount)
        else:
            return VerificationResult(ok=False, error=f"Unsupported network: {network}")
    except httpx.TimeoutException:
        logger.warning("Blockchain API timeout for tx %s on %s", tx_hash, network)
        return VerificationResult(ok=False, error="Blockchain API timeout — try again in a moment")
    except httpx.HTTPError as exc:
        logger.error("Blockchain API HTTP error for tx %s: %s", tx_hash, exc)
        return VerificationResult(ok=False, error="Blockchain API unavailable — try again later")
    except Exception as exc:
        logger.exception("Unexpected error verifying tx %s: %s", tx_hash, exc)
        return VerificationResult(ok=False, error="Verification error — try again later")


# ══════════════════════════════════════════════════════════════════════════════
# TRON / TRC20
# ══════════════════════════════════════════════════════════════════════════════

async def _verify_tron(tx_hash: str, wallet_address: str, min_amount: float) -> VerificationResult:
    """Verify USDT TRC20 transaction via TronGrid API (no API key needed)."""
    url = f"https://api.trongrid.io/v1/transactions/{tx_hash}"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, headers={"Accept": "application/json"})

    if resp.status_code == 404:
        return VerificationResult(ok=False, error="Transaction not found on TRON network", network="trc20")
    resp.raise_for_status()

    data = resp.json()
    tx_list = data.get("data", [])
    if not tx_list:
        return VerificationResult(ok=False, error="Transaction not found on TRON network", network="trc20")

    tx = tx_list[0]

    # Check success status
    ret = tx.get("ret", [{}])
    contract_ret = ret[0].get("contractRet", "") if ret else ""
    if contract_ret != "SUCCESS":
        return VerificationResult(ok=False, error=f"Transaction failed on TRON (status: {contract_ret})", network="trc20")

    # Check confirmations
    confirmations = tx.get("confirmations", 0)
    required = _CONFIRMATIONS["trc20"]
    if confirmations < required:
        return VerificationResult(
            ok=False,
            error=f"Transaction not yet confirmed ({confirmations}/{required} blocks)",
            confirmations=confirmations,
            network="trc20",
        )

    # Parse TRC20 transfer from contract data
    raw_data = tx.get("raw_data", {})
    contracts = raw_data.get("contract", [])
    if not contracts:
        return VerificationResult(ok=False, error="No contract data in transaction", network="trc20")

    contract = contracts[0]
    contract_type = contract.get("type", "")

    # TRC20 transfer: TriggerSmartContract
    if contract_type == "TriggerSmartContract":
        param = contract.get("parameter", {}).get("value", {})
        to_address = param.get("to_address") or ""
        data_hex   = param.get("data", "")

        # Decode transfer(address, uint256) — first 4 bytes = function selector
        # Next 32 bytes = address (padded), next 32 bytes = amount
        if len(data_hex) >= 136 and data_hex.startswith("a9059cbb"):
            recipient_hex = data_hex[32:72].lstrip("0")  # strip padding
            amount_hex    = data_hex[72:136]
            amount_sun    = int(amount_hex, 16) if amount_hex else 0
            amount_usdt   = amount_sun / 1_000_000  # USDT has 6 decimals on TRON

            # Convert TRON hex address to base58 for comparison
            # TronGrid returns to_address already in base58 format in some endpoints
            recipient_b58 = _tron_hex_to_base58(recipient_hex) if len(recipient_hex) == 40 else to_address

            if wallet_address.lower() not in (recipient_b58.lower(), to_address.lower()):
                return VerificationResult(
                    ok=False,
                    error=f"Payment sent to wrong address (expected {wallet_address[:10]}...)",
                    network="trc20",
                )
            if min_amount > 0 and amount_usdt < min_amount:
                return VerificationResult(
                    ok=False,
                    error=f"Insufficient amount: received {amount_usdt:.2f} USDT, expected {min_amount:.2f} USDT",
                    amount_received=f"{amount_usdt:.2f} USDT",
                    network="trc20",
                )
            return VerificationResult(
                ok=True, confirmations=confirmations,
                amount_received=f"{amount_usdt:.6f} USDT", network="trc20",
            )

    # Native TRX transfer
    if contract_type == "TransferContract":
        param = contract.get("parameter", {}).get("value", {})
        to_address = param.get("to_address", "")
        amount_sun = param.get("amount", 0)
        amount_trx = amount_sun / 1_000_000

        if wallet_address.lower() != to_address.lower():
            return VerificationResult(ok=False, error="Payment sent to wrong address", network="trc20")
        if min_amount > 0 and amount_trx < min_amount:
            return VerificationResult(
                ok=False,
                error=f"Insufficient amount: received {amount_trx:.6f} TRX, expected {min_amount:.6f}",
                amount_received=f"{amount_trx:.6f} TRX",
                network="trc20",
            )
        return VerificationResult(
            ok=True, confirmations=confirmations,
            amount_received=f"{amount_trx:.6f} TRX", network="trc20",
        )

    return VerificationResult(ok=False, error="Unrecognized transaction type on TRON", network="trc20")


def _tron_hex_to_base58(hex_address: str) -> str:
    """Convert 20-byte hex address to TRON base58check format (starts with T)."""
    import hashlib
    import base58  # pip install base58

    # TRON address = 0x41 prefix + 20 bytes
    raw = bytes.fromhex("41" + hex_address.zfill(40))
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return base58.b58encode(raw + checksum).decode()


# ══════════════════════════════════════════════════════════════════════════════
# Ethereum / BSC (EVM-compatible via Etherscan-style API)
# ══════════════════════════════════════════════════════════════════════════════

async def _verify_evm(
    tx_hash: str, wallet_address: str, min_amount: float, chain: str
) -> VerificationResult:
    """Verify ERC20/BEP20 transaction via Etherscan-compatible API."""
    if chain == "eth":
        base_url = "https://api.etherscan.io/api"
        api_key  = _ETHERSCAN_KEY   # set ETHERSCAN_API_KEY; empty = anonymous tier (5 req/s)
        net_name = "erc20"
        if not api_key:
            logger.debug("ETHERSCAN_API_KEY not set — using anonymous tier (rate-limited)")
    else:  # bsc
        base_url = "https://api.bscscan.com/api"
        api_key  = _BSCSCAN_KEY     # set BSCSCAN_API_KEY; empty = anonymous tier
        net_name = "bep20"
        if not api_key:
            logger.debug("BSCSCAN_API_KEY not set — using anonymous tier (rate-limited)")

    params = {
        "module":  "proxy",
        "action":  "eth_getTransactionByHash",
        "txhash":  tx_hash,
        "apikey":  api_key,
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(base_url, params=params)
    resp.raise_for_status()
    data = resp.json()

    tx = data.get("result")
    if not tx or tx == "0x0":
        return VerificationResult(ok=False, error=f"Transaction not found on {'Ethereum' if chain == 'eth' else 'BSC'}", network=net_name)

    # Check recipient
    to_addr = (tx.get("to") or "").lower()
    if wallet_address.lower() != to_addr:
        # Could be a token contract call — check input data for ERC20 transfer
        input_data = tx.get("input", "")
        if input_data.startswith("0xa9059cbb") and len(input_data) >= 138:
            recipient_hex = input_data[34:74]  # 20 bytes after selector + padding
            if wallet_address.lower().lstrip("0x") not in recipient_hex.lower():
                return VerificationResult(ok=False, error="Payment sent to wrong address", network=net_name)
            # Decode amount (wei or token units)
            amount_hex = input_data[74:138]
            amount_raw = int(amount_hex, 16) if amount_hex else 0
            amount = amount_raw / 1_000_000  # USDT has 6 decimals on ERC20
        else:
            # Native ETH transfer
            amount_wei = int(tx.get("value", "0x0"), 16)
            amount = amount_wei / 10**18
            if wallet_address.lower() != to_addr:
                return VerificationResult(ok=False, error="Payment sent to wrong address", network=net_name)
    else:
        amount_wei = int(tx.get("value", "0x0"), 16)
        amount = amount_wei / 10**18

    # Check block confirmations
    block_number_hex = tx.get("blockNumber")
    if not block_number_hex:
        return VerificationResult(ok=False, error="Transaction is still pending", network=net_name)

    # Get current block to calculate confirmations
    params_block = {"module": "proxy", "action": "eth_blockNumber", "apikey": api_key}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp2 = await client.get(base_url, params=params_block)
    resp2.raise_for_status()
    current_block_hex = resp2.json().get("result", "0x0")

    tx_block      = int(block_number_hex, 16)
    current_block = int(current_block_hex, 16)
    confirmations = max(0, current_block - tx_block + 1)
    required      = _CONFIRMATIONS[net_name]

    if confirmations < required:
        return VerificationResult(
            ok=False,
            error=f"Transaction not yet confirmed ({confirmations}/{required} blocks)",
            confirmations=confirmations,
            network=net_name,
        )

    if min_amount > 0 and amount < min_amount:
        return VerificationResult(
            ok=False,
            error=f"Insufficient amount: received {amount:.6f}, expected {min_amount:.6f}",
            amount_received=str(amount),
            network=net_name,
        )

    return VerificationResult(
        ok=True, confirmations=confirmations,
        amount_received=str(amount), network=net_name,
    )


# ══════════════════════════════════════════════════════════════════════════════
# TON
# ══════════════════════════════════════════════════════════════════════════════

async def _verify_ton(tx_hash: str, wallet_address: str, min_amount: float) -> VerificationResult:
    """Verify TON transaction via TON Center public API (no key required)."""
    url = "https://toncenter.com/api/v2/getTransactions"
    params = {
        "address": wallet_address,
        "limit":   20,
        "archival": "false",
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params=params)
    resp.raise_for_status()

    data = resp.json()
    if not data.get("ok"):
        return VerificationResult(ok=False, error="TON API error", network="ton")

    transactions = data.get("result", [])
    for tx in transactions:
        # TON tx_hash is stored in transaction_id.hash (base64)
        tx_id = tx.get("transaction_id", {})
        tx_hash_b64 = tx_id.get("hash", "")

        # Accept both base64 and hex representations
        import base64
        try:
            tx_hash_hex_from_b64 = base64.b64decode(tx_hash_b64).hex()
        except Exception:
            tx_hash_hex_from_b64 = ""

        if tx_hash.lower() not in (tx_hash_b64.lower(), tx_hash_hex_from_b64.lower()):
            continue

        # Found the transaction
        in_msg = tx.get("in_msg", {})
        amount_nanoton = int(in_msg.get("value", 0))
        amount_ton = amount_nanoton / 10**9

        if min_amount > 0 and amount_ton < min_amount:
            return VerificationResult(
                ok=False,
                error=f"Insufficient amount: received {amount_ton:.9f} TON, expected {min_amount:.9f}",
                amount_received=f"{amount_ton:.9f} TON",
                network="ton",
            )

        return VerificationResult(
            ok=True, confirmations=1,
            amount_received=f"{amount_ton:.9f} TON", network="ton",
        )

    return VerificationResult(ok=False, error="Transaction not found for this wallet on TON", network="ton")


# ══════════════════════════════════════════════════════════════════════════════
# Bitcoin
# ══════════════════════════════════════════════════════════════════════════════

async def _verify_btc(tx_hash: str, wallet_address: str, min_amount: float) -> VerificationResult:
    """Verify BTC transaction via Blockstream.info API (no API key needed)."""
    url = f"https://blockstream.info/api/tx/{tx_hash}"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url)

    if resp.status_code == 404:
        return VerificationResult(ok=False, error="Transaction not found on Bitcoin network", network="btc")
    resp.raise_for_status()

    tx = resp.json()
    status = tx.get("status", {})

    if not status.get("confirmed", False):
        return VerificationResult(ok=False, error="Bitcoin transaction is not yet confirmed", network="btc")

    # Get current block height for confirmation count
    url_height = "https://blockstream.info/api/blocks/tip/height"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp_h = await client.get(url_height)
    resp_h.raise_for_status()
    current_height = int(resp_h.text.strip())

    tx_block_height = status.get("block_height", current_height)
    confirmations   = max(0, current_height - tx_block_height + 1)
    required        = _CONFIRMATIONS["btc"]

    if confirmations < required:
        return VerificationResult(
            ok=False,
            error=f"Insufficient confirmations ({confirmations}/{required})",
            confirmations=confirmations,
            network="btc",
        )

    # Find output to our wallet
    vout = tx.get("vout", [])
    amount_sat = 0
    for output in vout:
        scriptpubkey_address = output.get("scriptpubkey_address", "")
        if scriptpubkey_address == wallet_address:
            amount_sat += output.get("value", 0)

    if amount_sat == 0:
        return VerificationResult(ok=False, error="No output found for the specified wallet address", network="btc")

    amount_btc = amount_sat / 10**8
    if min_amount > 0 and amount_btc < min_amount:
        return VerificationResult(
            ok=False,
            error=f"Insufficient amount: received {amount_btc:.8f} BTC, expected {min_amount:.8f}",
            amount_received=f"{amount_btc:.8f} BTC",
            network="btc",
        )

    return VerificationResult(
        ok=True, confirmations=confirmations,
        amount_received=f"{amount_btc:.8f} BTC", network="btc",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _parse_amount(amount_str: str) -> float:
    """Parse amount from strings like '5 USDT', '0.001 BTC', '100', ''.

    Returns 0.0 if amount is absent or unparseable (no minimum check applied).
    """
    if not amount_str:
        return 0.0
    # Extract first number from string
    match = re.search(r"[\d]+\.?[\d]*", amount_str.replace(",", "."))
    if match:
        try:
            return float(match.group())
        except ValueError:
            pass
    return 0.0
