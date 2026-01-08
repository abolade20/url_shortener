import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = "sqlite:///site.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True