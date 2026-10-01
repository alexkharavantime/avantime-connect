from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    mongo_uri: str = "mongodb://localhost:27017"
    db_name: str = "avantime_connect"
    # пул VPN-клиентов (уточнить по конфигу сервера)
    vpn_client_pool: str = "10.30.0.0/24"
    server_network: str = "10.40.0.0/24"
    rdp_host: str = "10.40.0.20"

    class Config:
        env_file = ".env"

settings = Settings()
