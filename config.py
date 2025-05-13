# Configuration file for global variables

USER_DB_FILE = "user_data.json"  # db file path
CREDENTIALS_FILE = "credentials.json"  # creds file path

class CurrentUser:
    _username = None
    
    @classmethod
    def get(cls):
        return cls._username
    
    @classmethod
    def set(cls, username):
        cls._username = username

# Maintain the original name as an alias
CURRENT_USER = CurrentUser