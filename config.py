import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a-secure-default-secret-key')
    DATABASE_FILE = 'blackbox.db'
    DEBUG = False