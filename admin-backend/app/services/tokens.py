import secrets

def new_invite_token() -> str:
    return secrets.token_urlsafe(24)
