from fastapi_csrf_protect import CsrfProtect
from pydantic import BaseModel

from app.config import settings


class CsrfSettings(BaseModel):
    secret_key: str = settings.CSRF_SECRET_KEY
    token_location: str = "body"  # For form submissions
    token_key: str = "csrf_token"  # Form field name


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()