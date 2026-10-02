from pydantic_settings import BaseSettings

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

    class Config:
        env_file = ".env"

settings = Settings()
