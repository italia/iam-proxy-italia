from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    LOGIN_URL: str
    LOGOUT_URL: str
    STATIC_URL: str = "/static"
    LOGIN_REDIRECT_URL: str = "/"
    LOGOUT_REDIRECT_URL: str = "/"
    SCOPE: str
    URL_REDIRECT: str
    CLIENT_SECRET: str
    CLIENT_ID: str

    class Config:
        env_file = ".env"

# istanza globale
settings = Settings()