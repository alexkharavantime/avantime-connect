from enum import Enum
from pydantic import BaseModel

class AppType(str, Enum):
    desktop = "desktop"
    remoteapp32 = "remoteapp32"
    remoteapp64 = "remoteapp64"

class UserCreate(BaseModel):
    login: str
    full_name: str
    app_type: AppType

class EnrollRequest(BaseModel):
    token: str
    public_key: str
    device_name: str

class EnrollResponse(BaseModel):
    vpn_ip: str
    server_public_key: str
    endpoint: str
    allowed_ips: str
    keepalive: int
    app_type: AppType
    rdp_host: str
