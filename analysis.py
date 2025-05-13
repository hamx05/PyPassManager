from tkinter import messagebox
from config import CURRENT_USER
from storage import loadCredentials
from crypto import RSAdecrypt

def analyzePasswords() -> str:
    """Decrypts passwords and analyzes their strength."""
    from utils import checkPasswordStrength
    current_user = CURRENT_USER.get()  # Get current user
    if not current_user:
        raise ValueError("No user is currently logged in")
    
    credentials = loadCredentials(current_user)
    if not credentials:
        return "No credentials found to analyze."
    
    weak_passwords = []
    average_passwords = []
    strong_passwords = []

    for cred in credentials:
        decrypted_password = RSAdecrypt(cred['password'], (cred['privatekey'], cred['modulus']))
        strength, _ = checkPasswordStrength(decrypted_password)

        website = cred['website']  # Get website name from the credential data
        
        if strength == "Weak":
            weak_passwords.append(website)
        elif strength == "Medium":
            average_passwords.append(website)
        elif strength == "Strong":
            strong_passwords.append(website)

    # Formatting the message
    message_parts = []
    if weak_passwords:
        message_parts.append(f"Weak passwords at: {', '.join(weak_passwords)}")
    if average_passwords:
        message_parts.append(f"Average passwords at: {', '.join(average_passwords)}")
    if strong_passwords:
        message_parts.append(f"Strong passwords at: {', '.join(strong_passwords)}")

    return "\n".join(message_parts) if message_parts else "All passwords are strong!"