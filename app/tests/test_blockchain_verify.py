"""
Tests for app/security/blockchain_verify.py

Uses pytest-httpx to mock all HTTP calls — no real network, no real money.
Run: pytest app/tests/test_blockchain_verify.py -v
"""
from __future__ import annotations

import re
import pytest
import httpx
from pytest_httpx import HTTPXMock

from app.security.blockchain_verify import (
    VerificationResult,
    verify_transaction,
    _parse_amount,
)


# ══════════════════════════════════════════════════════════════════════════════
# _parse_amount
# ══════════════════════════════════════════════════════════════════════════════

class TestParseAmount:
    def test_usdt_string(self):
        assert _parse_amount("5 USDT") == 5.0

    def test_btc_string(self):
        assert _parse_amount("0.001 BTC") == 0.001

    def test_number_only(self):
        assert _parse_amount("100") == 100.0

    def test_empty_string(self):
        assert _parse_amount("") == 0.0

    def test_none_like_free(self):
        assert _parse_amount("Free") == 0.0

    def test_comma_decimal(self):
        assert _parse_amount("1,5 TON") == 1.5

    def test_price_display(self):
        assert _parse_amount("10 USDT/month") == 10.0


# ══════════════════════════════════════════════════════════════════════════════
# verify_transaction — input validation
# ══════════════════════════════════════════════════════════════════════════════

class TestInputValidation:
    @pytest.mark.asyncio
    async def test_empty_tx_hash(self):
        result = await verify_transaction("", "TXwallet", "5 USDT", "USDT", "trc20")
        assert result.ok is False
        assert "required" in result.error.lower()

    @pytest.mark.asyncio
    async def test_invalid_tx_hash_format(self):
        result = await verify_transaction("not-a-hash!", "TXwallet", "5 USDT", "USDT", "trc20")
        assert result.ok is False
        assert "invalid" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unsupported_network(self, httpx_mock: HTTPXMock):
        result = await verify_transaction(
            "a" * 64, "wallet", "5 USDT", "USDT", "xmr"
        )
        assert result.ok is False
        assert "unsupported" in result.error.lower()


# ══════════════════════════════════════════════════════════════════════════════
# TRON / TRC20
# ══════════════════════════════════════════════════════════════════════════════

TRON_TX_HASH = "a" * 64
TRON_WALLET  = "TXYZwalletaddress123456789abcdef"

# Minimal TRC20 transfer calldata: selector + padded address + amount (5 USDT = 5_000_000 sun)
_TRON_TRANSFER_DATA = (
    "a9059cbb"                                          # transfer(address,uint256) selector
    + "000000000000000000000000" + "abcdef1234567890abcdef1234567890abcdef12"  # padded recipient
    + f"{5_000_000:064x}"                               # amount: 5 USDT
)

_TRON_SUCCESS_RESPONSE = {
    "data": [{
        "ret": [{"contractRet": "SUCCESS"}],
        "confirmations": 25,
        "raw_data": {
            "contract": [{
                "type": "TriggerSmartContract",
                "parameter": {
                    "value": {
                        "to_address": TRON_WALLET,
                        "data": _TRON_TRANSFER_DATA,
                    }
                }
            }]
        }
    }]
}

class TestTronVerification:
    @pytest.mark.asyncio
    async def test_not_found(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://api.trongrid.io/v1/transactions/{TRON_TX_HASH}",
            status_code=404,
        )
        result = await verify_transaction(TRON_TX_HASH, TRON_WALLET, "5 USDT", "USDT", "trc20")
        assert result.ok is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_failed_transaction(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://api.trongrid.io/v1/transactions/{TRON_TX_HASH}",
            json={"data": [{"ret": [{"contractRet": "REVERT"}], "confirmations": 30, "raw_data": {"contract": []}}]},
        )
        result = await verify_transaction(TRON_TX_HASH, TRON_WALLET, "5 USDT", "USDT", "trc20")
        assert result.ok is False
        assert "failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_insufficient_confirmations(self, httpx_mock: HTTPXMock):
        response = {
            "data": [{
                "ret": [{"contractRet": "SUCCESS"}],
                "confirmations": 5,   # less than required 19
                "raw_data": {"contract": [{"type": "TriggerSmartContract", "parameter": {"value": {"data": ""}}}]}
            }]
        }
        httpx_mock.add_response(
            url=f"https://api.trongrid.io/v1/transactions/{TRON_TX_HASH}",
            json=response,
        )
        result = await verify_transaction(TRON_TX_HASH, TRON_WALLET, "5 USDT", "USDT", "trc20")
        assert result.ok is False
        assert "confirmed" in result.error.lower()
        assert result.confirmations == 5

    @pytest.mark.asyncio
    async def test_wrong_recipient(self, httpx_mock: HTTPXMock):
        data = _TRON_SUCCESS_RESPONSE.copy()
        httpx_mock.add_response(
            url=f"https://api.trongrid.io/v1/transactions/{TRON_TX_HASH}",
            json=data,
        )
        result = await verify_transaction(
            TRON_TX_HASH, "TWRONGwallet999", "5 USDT", "USDT", "trc20"
        )
        assert result.ok is False
        assert "wrong address" in result.error.lower()

    @pytest.mark.asyncio
    async def test_insufficient_amount(self, httpx_mock: HTTPXMock):
        # Build calldata with only 1 USDT
        low_amount_data = (
            "a9059cbb"
            + "000000000000000000000000" + "abcdef1234567890abcdef1234567890abcdef12"
            + f"{1_000_000:064x}"  # 1 USDT
        )
        response = {
            "data": [{
                "ret": [{"contractRet": "SUCCESS"}],
                "confirmations": 25,
                "raw_data": {
                    "contract": [{
                        "type": "TriggerSmartContract",
                        "parameter": {"value": {"to_address": TRON_WALLET, "data": low_amount_data}}
                    }]
                }
            }]
        }
        httpx_mock.add_response(
            url=f"https://api.trongrid.io/v1/transactions/{TRON_TX_HASH}",
            json=response,
        )
        result = await verify_transaction(TRON_TX_HASH, TRON_WALLET, "5 USDT", "USDT", "trc20")
        assert result.ok is False
        assert "insufficient" in result.error.lower()

    @pytest.mark.asyncio
    async def test_timeout(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(
            httpx.TimeoutException("timeout"),
            url=f"https://api.trongrid.io/v1/transactions/{TRON_TX_HASH}",
        )
        result = await verify_transaction(TRON_TX_HASH, TRON_WALLET, "5 USDT", "USDT", "trc20")
        assert result.ok is False
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_empty_data_response(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://api.trongrid.io/v1/transactions/{TRON_TX_HASH}",
            json={"data": []},
        )
        result = await verify_transaction(TRON_TX_HASH, TRON_WALLET, "5 USDT", "USDT", "trc20")
        assert result.ok is False
        assert "not found" in result.error.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Ethereum / ERC20
# ══════════════════════════════════════════════════════════════════════════════

ETH_TX_HASH  = "b" * 64
ETH_WALLET   = "0xAbCdEf1234567890abcdef1234567890AbCdEf12"

_ETH_API = re.compile(r"https://api\.etherscan\.io/api")
_BSC_API = re.compile(r"https://api\.bscscan\.com/api")
_TON_API = re.compile(r"https://toncenter\.com/api")

class TestEthereumVerification:
    @pytest.mark.asyncio
    async def test_not_found(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_ETH_API, json={"result": None})
        result = await verify_transaction(ETH_TX_HASH, ETH_WALLET, "0.01 ETH", "ETH", "erc20")
        assert result.ok is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_pending_transaction(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_ETH_API,
            json={"result": {"to": ETH_WALLET.lower(), "value": hex(int(0.01 * 10**18)), "blockNumber": None, "input": "0x"}},
        )
        result = await verify_transaction(ETH_TX_HASH, ETH_WALLET, "0.01 ETH", "ETH", "erc20")
        assert result.ok is False
        assert "pending" in result.error.lower()

    @pytest.mark.asyncio
    async def test_insufficient_confirmations(self, httpx_mock: HTTPXMock):
        # tx at block 100, current block 105 → 6 confirmations < 12 required
        httpx_mock.add_response(
            url=_ETH_API,
            json={"result": {"to": ETH_WALLET.lower(), "value": hex(int(0.01 * 10**18)), "blockNumber": hex(100), "input": "0x"}},
        )
        httpx_mock.add_response(url=_ETH_API, json={"result": hex(105)})
        result = await verify_transaction(ETH_TX_HASH, ETH_WALLET, "0.01 ETH", "ETH", "erc20")
        assert result.ok is False
        assert "confirmed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_success(self, httpx_mock: HTTPXMock):
        # tx at block 100, current block 120 → 21 confirmations > 12
        httpx_mock.add_response(
            url=_ETH_API,
            json={"result": {"to": ETH_WALLET.lower(), "value": hex(int(0.05 * 10**18)), "blockNumber": hex(100), "input": "0x"}},
        )
        httpx_mock.add_response(url=_ETH_API, json={"result": hex(120)})
        result = await verify_transaction(ETH_TX_HASH, ETH_WALLET, "0.01 ETH", "ETH", "erc20")
        assert result.ok is True
        assert result.confirmations == 21

    @pytest.mark.asyncio
    async def test_network_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), url=_ETH_API)
        result = await verify_transaction(ETH_TX_HASH, ETH_WALLET, "0.01 ETH", "ETH", "erc20")
        assert result.ok is False
        assert "unavailable" in result.error.lower()


# ══════════════════════════════════════════════════════════════════════════════
# BSC / BEP20
# ══════════════════════════════════════════════════════════════════════════════

BSC_TX_HASH = "c" * 64
BSC_WALLET  = "0xBSCwallet1234567890abcdef1234567890bscwlt"

class TestBSCVerification:
    @pytest.mark.asyncio
    async def test_not_found(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_BSC_API, json={"result": None})
        result = await verify_transaction(BSC_TX_HASH, BSC_WALLET, "5 USDT", "USDT", "bep20")
        assert result.ok is False

    @pytest.mark.asyncio
    async def test_success_confirmed(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_BSC_API,
            json={"result": {"to": BSC_WALLET.lower(), "value": hex(int(10 * 10**18)), "blockNumber": hex(200), "input": "0x"}},
        )
        httpx_mock.add_response(url=_BSC_API, json={"result": hex(220)})  # 21 confirmations > 15
        result = await verify_transaction(BSC_TX_HASH, BSC_WALLET, "0 USDT", "USDT", "bep20")
        assert result.ok is True


# ══════════════════════════════════════════════════════════════════════════════
# TON
# ══════════════════════════════════════════════════════════════════════════════

TON_TX_HASH = "d" * 64
TON_WALLET  = "EQDtTestWalletAddressTON1234567890abcdef"

class TestTONVerification:
    @pytest.mark.asyncio
    async def test_not_found(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_TON_API, json={"ok": True, "result": []})
        result = await verify_transaction(TON_TX_HASH, TON_WALLET, "1 TON", "TON", "ton")
        assert result.ok is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_api_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_TON_API, json={"ok": False, "error": "internal"})
        result = await verify_transaction(TON_TX_HASH, TON_WALLET, "1 TON", "TON", "ton")
        assert result.ok is False
        assert "ton api error" in result.error.lower()

    @pytest.mark.asyncio
    async def test_success_by_hash(self, httpx_mock: HTTPXMock):
        import base64
        tx_hash_b64 = base64.b64encode(bytes.fromhex(TON_TX_HASH[:64])).decode()
        httpx_mock.add_response(
            url=_TON_API,
            json={"ok": True, "result": [{"transaction_id": {"hash": tx_hash_b64}, "in_msg": {"value": str(2 * 10**9)}}]},
        )
        result = await verify_transaction(TON_TX_HASH[:64], TON_WALLET, "1 TON", "TON", "ton")
        assert result.ok is True
        assert "2.0" in result.amount_received or "2" in result.amount_received

    @pytest.mark.asyncio
    async def test_insufficient_amount(self, httpx_mock: HTTPXMock):
        import base64
        tx_hash_b64 = base64.b64encode(bytes.fromhex(TON_TX_HASH[:64])).decode()
        httpx_mock.add_response(
            url=_TON_API,
            json={"ok": True, "result": [{"transaction_id": {"hash": tx_hash_b64}, "in_msg": {"value": str(int(0.5 * 10**9))}}]},
        )
        result = await verify_transaction(TON_TX_HASH[:64], TON_WALLET, "1 TON", "TON", "ton")
        assert result.ok is False
        assert "insufficient" in result.error.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Bitcoin
# ══════════════════════════════════════════════════════════════════════════════

BTC_TX_HASH = "e" * 64
BTC_WALLET  = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

class TestBitcoinVerification:
    @pytest.mark.asyncio
    async def test_not_found(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://blockstream.info/api/tx/{BTC_TX_HASH}",
            status_code=404,
        )
        result = await verify_transaction(BTC_TX_HASH, BTC_WALLET, "0.001 BTC", "BTC", "btc")
        assert result.ok is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unconfirmed(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://blockstream.info/api/tx/{BTC_TX_HASH}",
            json={
                "status": {"confirmed": False},
                "vout": [{"scriptpubkey_address": BTC_WALLET, "value": 100_000}],
            },
        )
        result = await verify_transaction(BTC_TX_HASH, BTC_WALLET, "0.001 BTC", "BTC", "btc")
        assert result.ok is False
        assert "confirmed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_insufficient_confirmations(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://blockstream.info/api/tx/{BTC_TX_HASH}",
            json={
                "status": {"confirmed": True, "block_height": 800_000},
                "vout": [{"scriptpubkey_address": BTC_WALLET, "value": 100_000}],
            },
        )
        httpx_mock.add_response(
            url="https://blockstream.info/api/blocks/tip/height",
            text="800001",   # only 2 confirmations < 3 required
        )
        result = await verify_transaction(BTC_TX_HASH, BTC_WALLET, "0.001 BTC", "BTC", "btc")
        assert result.ok is False
        assert "confirmations" in result.error.lower()

    @pytest.mark.asyncio
    async def test_wrong_wallet(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://blockstream.info/api/tx/{BTC_TX_HASH}",
            json={
                "status": {"confirmed": True, "block_height": 800_000},
                "vout": [{"scriptpubkey_address": "bc1qWRONGwallet", "value": 100_000}],
            },
        )
        httpx_mock.add_response(
            url="https://blockstream.info/api/blocks/tip/height",
            text="800010",
        )
        result = await verify_transaction(BTC_TX_HASH, BTC_WALLET, "0.001 BTC", "BTC", "btc")
        assert result.ok is False
        assert "no output" in result.error.lower()

    @pytest.mark.asyncio
    async def test_success(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://blockstream.info/api/tx/{BTC_TX_HASH}",
            json={
                "status": {"confirmed": True, "block_height": 800_000},
                "vout": [
                    {"scriptpubkey_address": "bc1other", "value": 50_000},
                    {"scriptpubkey_address": BTC_WALLET, "value": 150_000},  # 0.0015 BTC
                ],
            },
        )
        httpx_mock.add_response(
            url="https://blockstream.info/api/blocks/tip/height",
            text="800010",  # 11 confirmations > 3
        )
        result = await verify_transaction(BTC_TX_HASH, BTC_WALLET, "0.001 BTC", "BTC", "btc")
        assert result.ok is True
        assert result.confirmations == 11
        assert "0.00150000" in result.amount_received

    @pytest.mark.asyncio
    async def test_insufficient_amount(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"https://blockstream.info/api/tx/{BTC_TX_HASH}",
            json={
                "status": {"confirmed": True, "block_height": 800_000},
                "vout": [{"scriptpubkey_address": BTC_WALLET, "value": 50_000}],  # 0.0005 BTC < 0.001
            },
        )
        httpx_mock.add_response(
            url="https://blockstream.info/api/blocks/tip/height",
            text="800010",
        )
        result = await verify_transaction(BTC_TX_HASH, BTC_WALLET, "0.001 BTC", "BTC", "btc")
        assert result.ok is False
        assert "insufficient" in result.error.lower()


# ══════════════════════════════════════════════════════════════════════════════
# VerificationResult dataclass
# ══════════════════════════════════════════════════════════════════════════════

class TestVerificationResult:
    def test_default_values(self):
        r = VerificationResult(ok=True)
        assert r.error is None
        assert r.confirmations == 0
        assert r.amount_received == ""
        assert r.network == ""

    def test_failure(self):
        r = VerificationResult(ok=False, error="bad tx")
        assert r.ok is False
        assert r.error == "bad tx"
