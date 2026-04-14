from typing import List
from pydantic import BaseModel


class SSOProviderConfig(BaseModel):
    type: str                  # google | github | apple | microsoft | oidc
    client_id: str     = ""
    client_secret: str = ""
    tenant_id: str     = ""   # Microsoft
    team_id: str       = ""   # Apple
    key_id: str        = ""   # Apple
    private_key: str   = ""   # Apple
    discovery_url: str = ""   # Generic OIDC


class SSOConfig(BaseModel):
    passkeys_enabled: bool = True
    providers: List[SSOProviderConfig] = []


class SelfSignedRequest(BaseModel):
    hostname: str  = ""
    org_name: str  = "Vortex Node"
    install_ca: bool = True
    admin_password: str = ""  # пароль администратора для установки CA без терминала


class LetsEncryptRequest(BaseModel):
    domain: str
    email: str
    staging: bool = False


class ManualCertRequest(BaseModel):
    cert_path: str
    key_path: str

class NodeConfig(BaseModel):
    device_name: str
    port: int = 8000
    host: str = "0.0.0.0"
    max_file_mb: int = 100
    udp_port: int = 4200
    environment: str = "development"
    network_mode: str = "local"
    registration_mode: str = "open"
    invite_code: str = ""
    obfuscation_enabled: bool = True