# node_setup/ssl_manager.py
# Тонкий модуль реэкспорта — сохраняет обратную совместимость.
# Все реализации вынесены в ssl_result, ssl_generate, ssl_install, ssl_utils.

from node_setup.ssl_generate import (
    generate_letsencrypt,
    generate_self_signed,
    generate_with_mkcert,
    use_manual_cert,
)
from node_setup.ssl_install import (
    _install_ca_debian,
    _install_ca_linux_generic,
    _install_ca_macos,
    _install_ca_windows,
    get_ca_install_instructions,
    install_ca_to_trust_store,
)
from node_setup.ssl_result import SSLResult, _get_system, _local_ips
from node_setup.ssl_utils import (
    _get_mkcert_ca_path,
    check_cert_expiry,
    detect_available_methods,
)

__all__ = [
    "SSLResult",
    "_get_mkcert_ca_path",
    "_get_system",
    "_install_ca_debian",
    "_install_ca_linux_generic",
    "_install_ca_macos",
    "_install_ca_windows",
    "_local_ips",
    "check_cert_expiry",
    "detect_available_methods",
    "generate_letsencrypt",
    "generate_self_signed",
    "generate_with_mkcert",
    "get_ca_install_instructions",
    "install_ca_to_trust_store",
    "use_manual_cert",
]
