from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    mongo_uri: str = "mongodb://localhost:27017"
    db_name: str = "avantime_connect"
    vpn_client_pool: str = "10.30.0.0/24"
    server_network: str = "10.40.0.0/24"
    rdp_host: str = "10.40.0.20"
    wg_server_public_key: str = "AloRLEn2FY2jZ0jVIhuhtDUOnIdZfv2kb6QGCgT2vjw="
    wg_endpoint: str = "65.21.22.189:51820"
    wg_keepalive: int = 25
    wg_allowed_ips: str = "10.40.0.0/24"
    reserved_ips: str = "10.30.0.1,10.30.0.2,10.30.0.3,10.30.0.4,10.30.0.5,10.30.0.6,10.30.0.10"
    invite_ttl_hours: int = 72
    # Seconds; only replays a completed enrollment, never extends a new invitation.
    enroll_recovery_ttl: int = Field(default=24 * 60 * 60, gt=0)

    # Fail closed until SSH configuration and an admin credential are provided.
    wg_mode: Literal["disabled", "ssh"] = "disabled"
    wg_ssh_host: str = "10.20.0.2"
    wg_ssh_port: int = 22
    wg_ssh_user: str = "avantime-wg"
    wg_ssh_key_file: str = "/run/secrets/wg_ssh_key"
    wg_ssh_known_hosts: str = "/run/secrets/wg_known_hosts"
    admin_api_token: str = ""
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
