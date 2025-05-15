import sqlite3
import os
import base64
from config import DB_FILE, CURRENT_USER
from crypto import md5, encrypt_data, decrypt_data, generate_aes_key

def initialize_database():
    """
    Creates the database and necessary tables if they don't exist.
    """
    # Only create directory if DB_FILE has a directory component
    db_dir = os.path.dirname(DB_FILE)
    if db_dir:  # Only try to create directory if there is one specified
        os.makedirs(db_dir, exist_ok=True)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        encryption_key TEXT NOT NULL
    )
    ''')
    
    # Check if the old credentials table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'")
    old_table_exists = cursor.fetchone() is not None
    
    if old_table_exists:
        # Check if we need to migrate (check if encrypted_website column exists)
        cursor.execute("PRAGMA table_info(credentials)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if "encrypted_website" not in columns:
            # We need to migrate data from old schema to new schema
            migrate_credentials_data(conn, cursor)
        else:
            # Table already has the new schema, no migration needed
            pass
    else:
        # Create new credentials table with all fields encrypted
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            encrypted_website TEXT NOT NULL,
            encrypted_site_username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        )
        ''')
    
    conn.commit()
    conn.close()

def migrate_credentials_data(conn, cursor):
    """
    Migrates data from the old credentials schema to the new schema with all fields encrypted.
    """
    # Rename the old table
    cursor.execute("ALTER TABLE credentials RENAME TO credentials_old")
    
    # Create the new table
    cursor.execute('''
    CREATE TABLE credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        encrypted_website TEXT NOT NULL,
        encrypted_site_username TEXT NOT NULL,
        encrypted_password TEXT NOT NULL,
        FOREIGN KEY (username) REFERENCES users(username)
    )
    ''')
    
    # Get all users to migrate their data
    cursor.execute("SELECT username, encryption_key FROM users")
    users = cursor.fetchall()
    
    for user, key_b64 in users:
        # Get the encryption key
        key = base64.b64decode(key_b64)
        
        # Get all credentials for this user
        cursor.execute(
            "SELECT id, website, site_username, encrypted_password FROM credentials_old WHERE username = ?",
            (user,)
        )
        
        credentials = cursor.fetchall()
        
        # Migrate each credential
        for cred_id, website, site_username, encrypted_password in credentials:
            # Encrypt the website and site_username
            encrypted_website = encrypt_data(website, key)
            encrypted_site_username = encrypt_data(site_username, key)
            
            # Insert into the new table
            cursor.execute(
                "INSERT INTO credentials (id, username, encrypted_website, encrypted_site_username, encrypted_password) VALUES (?, ?, ?, ?, ?)",
                (cred_id, user, encrypted_website, encrypted_site_username, encrypted_password)
            )
    
    # Drop the old table
    cursor.execute("DROP TABLE credentials_old")
    
    conn.commit()

def user_exists(username):
    """
    Checks if a user exists in the database.
    
    Args:
        username (str): The username to check.
        
    Returns:
        bool: True if the user exists, False otherwise.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
    count = cursor.fetchone()[0]
    
    conn.close()
    
    return count > 0

def any_users_exist():
    """
    Checks if any users exist in the database.
    
    Returns:
        bool: True if at least one user exists, False otherwise.
    """
    # Make sure the database exists
    if not os.path.exists(DB_FILE):
        return False
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    except sqlite3.OperationalError:
        # Table doesn't exist yet
        conn.close()
        return False

def add_user(username, password):
    """
    Adds a new user to the database.
    
    Args:
        username (str): The username for the new user.
        password (str): The password for the new user.
        
    Returns:
        bool: True if the user was added successfully, False otherwise.
    """
    # Check if the user already exists
    if user_exists(username):
        raise ValueError("Username already exists. Choose a different one.")
    
    # Hash the password
    password_hash = md5(password)
    
    # Generate an encryption key for this user
    key = generate_aes_key()
    key_b64 = base64.b64encode(key).decode('utf-8')
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)",
        (username, password_hash, key_b64)
    )
    
    conn.commit()
    conn.close()
    
    return True

def validate_user(username, password):
    """
    Validates a user's credentials.
    
    Args:
        username (str): The username to validate.
        password (str): The password to validate.
        
    Returns:
        bool: True if the credentials are valid, False otherwise.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT password_hash, encryption_key FROM users WHERE username = ?",
        (username,)
    )
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
    
    stored_hash, key_b64 = result
    
    # Hash the provided password and compare
    if md5(password) == stored_hash:
        # Store the encryption key in the CurrentUser class
        key = base64.b64decode(key_b64)
        CURRENT_USER.set_key(key)
        return True
    
    return False

def add_credential(website, site_username, password):
    """
    Adds a new credential to the database with all fields encrypted.
    
    Args:
        website (str): The website for the credential.
        site_username (str): The username for the website.
        password (str): The password for the website.
        
    Returns:
        bool: True if the credential was added successfully, False otherwise.
    """
    current_user = CURRENT_USER.get()
    if not current_user:
        raise ValueError("No user is currently logged in")
    
    # Get the encryption key
    key = CURRENT_USER.get_key()
    
    # Encrypt all fields
    encrypted_website = encrypt_data(website, key)
    encrypted_site_username = encrypt_data(site_username, key)
    encrypted_password = encrypt_data(password, key)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO credentials (username, encrypted_website, encrypted_site_username, encrypted_password) VALUES (?, ?, ?, ?)",
        (current_user, encrypted_website, encrypted_site_username, encrypted_password)
    )
    
    conn.commit()
    conn.close()
    
    return True

def get_credentials(search_term=None):
    """
    Gets all credentials for the current user, optionally filtered by a search term.
    
    Args:
        search_term (str, optional): A term to search for in website or username.
        
    Returns:
        list: A list of dictionaries containing credential information.
    """
    current_user = CURRENT_USER.get()
    if not current_user:
        raise ValueError("No user is currently logged in")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Get all credentials for the current user
    cursor.execute(
        "SELECT id, encrypted_website, encrypted_site_username, encrypted_password FROM credentials WHERE username = ?",
        (current_user,)
    )
    
    rows = cursor.fetchall()
    conn.close()
    
    # Get the encryption key
    key = CURRENT_USER.get_key()
    
    # Decrypt all fields and format results
    credentials = []
    for row in rows:
        id, encrypted_website, encrypted_site_username, encrypted_password = row
        
        # Decrypt all fields
        website = decrypt_data(encrypted_website, key)
        site_username = decrypt_data(encrypted_site_username, key)
        password = decrypt_data(encrypted_password, key)
        
        # If search term is provided, filter results
        if search_term and search_term.lower() not in website.lower() and search_term.lower() not in site_username.lower():
            continue
        
        credentials.append({
            "id": id,
            "website": website,
            "username": site_username,
            "password": password
        })
    
    return credentials

def delete_credential(credential_id):
    """
    Deletes a credential from the database.
    
    Args:
        credential_id (int): The ID of the credential to delete.
        
    Returns:
        bool: True if the credential was deleted successfully, False otherwise.
    """
    current_user = CURRENT_USER.get()
    if not current_user:
        raise ValueError("No user is currently logged in")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Verify the credential belongs to the current user
    cursor.execute(
        "SELECT COUNT(*) FROM credentials WHERE id = ? AND username = ?",
        (credential_id, current_user)
    )
    
    if cursor.fetchone()[0] == 0:
        conn.close()
        raise ValueError("Credential not found or does not belong to the current user")
    
    # Delete the credential
    cursor.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
    
    conn.commit()
    conn.close()
    
    return True
