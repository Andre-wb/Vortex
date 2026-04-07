"""
app/security/tor_hidden_service.py — Automatic Tor Hidden Service (.onion).

When TOR_HIDDEN_SERVICE=true and Tor is running with a control port,
Vortex automatically creates an ephemeral .onion address at startup.

The hidden service is ephemeral — the .onion address changes on restart
unless TOR_HS_PERSISTENT=true (requires Tor data directory access).

Config:
  TOR_HIDDEN_SERVICE=true      — enable automatic .onion
  TOR_CONTROL_PORT=9051        — Tor control port
  TOR_CONTROL_PASSWORD=...     — Tor control auth password
  TOR_HS_PERSISTENT=false      — persist .onion across restarts
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_TOR_HS_ENABLED = os.getenv("TOR_HIDDEN_SERVICE", "false").lower() in ("1", "true", "yes")
_TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))
_TOR_CONTROL_PASSWORD = os.getenv("TOR_CONTROL_PASSWORD", "")
_TOR_HS_PERSISTENT = os.getenv("TOR_HS_PERSISTENT", "false").lower() in ("1", "true", "yes")


class TorHiddenService:
    """Manage an ephemeral Tor hidden service via the Tor control protocol."""

    def __init__(self) -> None:
        self.onion_address: str | None = None
        self._controller = None
        self._service_id: str | None = None

    async def start(self, listen_port: int = 9000) -> str | None:
        """Create a Tor hidden service pointing to listen_port.

        Returns the .onion address or None if Tor is unavailable.
        """
        if not _TOR_HS_ENABLED:
            return None

        try:
            from stem.control import Controller

            self._controller = Controller.from_port(port=_TOR_CONTROL_PORT)
            if _TOR_CONTROL_PASSWORD:
                self._controller.authenticate(password=_TOR_CONTROL_PASSWORD)
            else:
                self._controller.authenticate()

            kwargs: dict = {}
            if not _TOR_HS_PERSISTENT:
                kwargs["discard_key"] = True

            response = self._controller.create_ephemeral_hidden_service(
                {80: listen_port},
                await_publication=False,
                **kwargs,
            )
            self._service_id = response.service_id
            self.onion_address = f"{response.service_id}.onion"

            logger.info(
                "Tor Hidden Service active: http://%s → 127.0.0.1:%d",
                self.onion_address, listen_port,
            )
            return self.onion_address

        except ImportError:
            logger.info("stem library not installed — Tor Hidden Service disabled")
            return None
        except Exception as e:
            logger.warning("Tor Hidden Service failed: %s", e)
            return None

    async def stop(self) -> None:
        """Remove the hidden service and close the controller."""
        if self._controller and self._service_id:
            try:
                self._controller.remove_ephemeral_hidden_service(self._service_id)
                logger.info("Tor Hidden Service removed: %s", self.onion_address)
            except Exception as e:
                logger.warning("Failed to remove Tor HS: %s", e)
            finally:
                try:
                    self._controller.close()
                except Exception:
                    pass
                self._controller = None
                self._service_id = None

    def get_status(self) -> dict:
        """Return hidden service status."""
        return {
            "enabled": _TOR_HS_ENABLED,
            "active": self.onion_address is not None,
            "onion_address": self.onion_address,
            "persistent": _TOR_HS_PERSISTENT,
        }


# Global instance
tor_hidden_service = TorHiddenService()
