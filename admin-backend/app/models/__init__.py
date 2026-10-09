from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

class AppType(str, Enum):
    desktop = "desktop"
    remoteapp32 = "remoteapp32"
    remoteapp64 = "remoteapp64"

class AccessSettings(BaseModel):
    environments: list[str] = Field(default_factory=lambda: ['prod'])

    @field_validator('environments')
    @classmethod
    def validate_environments(cls, value):
        if not value or len(value) != len(set(value)) or any(v not in ('dev', 'prod') for v in value):
            raise ValueError('Choose DEV, PROD, or both')
        return sorted(value)

class UserCreate(AccessSettings):
    login: str
    full_name: str
    app_type: AppType

class EnrollRequest(BaseModel):
    token: str
    public_key: str
    device_name: str

class AccessUpdate(AccessSettings):
    expected_revision: int = Field(ge=0)

class EnrollResponse(BaseModel):
    vpn_ip: str
    server_public_key: str
    endpoint: str
    allowed_ips: str
    keepalive: int
    app_type: AppType
    rdp_host: str
    environments: list[str] | None = None
    access_revision: int = 0

class EnrollSnapshot(EnrollResponse):
    enrolled_token: str
    public_key: str
    device_name: str
    completed_at: datetime
