# Configuration file for global variables

# Database file path
DB_FILE = "password_manager.db"

class CurrentUser:
    _username = None
    _encryption_key = None
    
    @classmethod
    def get(cls):
        return cls._username
    
    @classmethod
    def set(cls, username):
        cls._username = username
    
    @classmethod
    def get_key(cls):
        return cls._encryption_key
    
    @classmethod
    def set_key(cls, key):
        cls._encryption_key = key

# Maintain the original name as an alias
CURRENT_USER = CurrentUser
