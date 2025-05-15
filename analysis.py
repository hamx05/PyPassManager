from tkinter import messagebox
from config import CURRENT_USER
from database import get_credentials

def analyzePasswords() -> str:
    """Decrypts passwords and analyzes their strength."""
    from utils import checkPasswordStrength
    current_user = CURRENT_USER.get()  # Get current user
    if not current_user:
        return "No user is currently logged in"
    
    try:
        # Get credentials from the database
        credentials = get_credentials()
        
        if not credentials:
            return "No credentials found to analyze."
        
        weak_passwords = []
        average_passwords = []
        strong_passwords = []

        for cred in credentials:
            # Password is already decrypted by get_credentials
            password = cred['password']
            strength, _ = checkPasswordStrength(password)
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
    except Exception as e:
        return f"Error analyzing passwords: {str(e)}"
