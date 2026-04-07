# node_setup/ssl_manager.py
# ==============================================================================
# Тонкий модуль реэкспорта — сохраняет обратную совместимость.
# Все реализации вынесены в ssl_result, ssl_generate, ssl_install, ssl_utils.
# ==============================================================================

from node_setup.ssl_result import SSLResult, _local_ips, _get_system  # noqa: F401
from node_setup.ssl_generate import (  # noqa: F401
    generate_self_signed,
    generate_with_mkcert,
    generate_letsencrypt,
    use_manual_cert,
)
from node_setup.ssl_install import (  # noqa: F401
    install_ca_to_trust_store,
    _install_ca_macos,
    _install_ca_windows,
    _install_ca_debian,
    _install_ca_linux_generic,
    get_ca_install_instructions,
)
from node_setup.ssl_utils import (  # noqa: F401
    check_cert_expiry,
    detect_available_methods,
    _get_mkcert_ca_path,
)

__all__ = [
    "SSLResult",
    "_local_ips",
    "_get_system",
    "generate_self_signed",
    "generate_with_mkcert",
    "generate_letsencrypt",
    "use_manual_cert",
    "install_ca_to_trust_store",
    "_install_ca_macos",
    "_install_ca_windows",
    "_install_ca_debian",
    "_install_ca_linux_generic",
    "get_ca_install_instructions",
    "check_cert_expiry",
    "detect_available_methods",
    "_get_mkcert_ca_path",
]
