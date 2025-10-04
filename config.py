import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a-secure-default-secret-key')
    DATABASE_FILE = 'blackbox.db'
    BLACKBOX_FILE = 'blackbox-targets.yml'
    DEBUG = False