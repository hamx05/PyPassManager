import re
import string
import random
import pyperclip
import tkinter as tk
from tkinter import ttk, messagebox
from config import CURRENT_USER
from database import any_users_exist, add_user, validate_user

def ifUsersExist() -> bool:
    """
    Checks if any users exist in the database.

    Returns:
        bool: True if at least one user exists, otherwise False.
    """
    return any_users_exist()

def storeLoginCredentials(user_data: dict) -> None:
    """
    Stores user data (username and password) in the database.

    Args:
        user_data (dict): A dictionary containing the username and password_hash.
    """
    username = user_data["username"]
    password_hash = user_data["password_hash"]
    
    # The password hash is already computed, but add_user expects the raw password
    # We'll need to modify this approach
    try:
        add_user(username, password_hash)
    except ValueError as e:
        raise ValueError(str(e))

def validatePasskey(passkey: str) -> tuple[bool, str]:
    """
    Validates a passkey based on the following criteria:
    - Minimum length: 8 characters
    - Maximum length: 25 characters
    - At least one uppercase letter
    - At least one number
    - At least one special character

    Args:
        passkey (str): The passkey to validate.

    Returns:
        tuple: A tuple containing a boolean (True if valid) and a string (reason if invalid, or "Valid").
    """
    # Check length
    if not (8 <= len(passkey) <= 25):
        return False, "Passkey must be between 8 and 25 characters."

    # Check for at least one uppercase letter
    if not any(char.isupper() for char in passkey):
        return False, "Passkey must include at least one uppercase letter."

    # Check for at least one digit
    if not any(char.isdigit() for char in passkey):
        return False, "Passkey must include at least one number."

    # Check for at least one special character
    if not re.search(r"[!#\"$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]", passkey):
        return False, "Passkey must include at least one special character."

    return True, "Valid"

def isUserValid(username: str, password: str) -> bool:
    """
    Validates the user by checking the username and password in the database.

    Args:
        username (str): The entered username.
        password (str): The entered password.

    Returns:
        bool: True if the username and password match the stored data, False otherwise.
    """
    try:
        return validate_user(username, password)
    except Exception as e:
        print(f"*** ERROR: Failed to validate user. {e}")
        return False

def checkPasswordStrength(password: str) -> tuple:
    """Checks the strength of the password and returns strength and a reason."""
    if len(password) == 0:
        return "Empty", "None"
    elif len(password) < 8:
        return "Weak", "Password too short"
    elif not any(char.isdigit() for char in password):
        return "Medium", "Password needs a digit"
    elif not any(char.isupper() for char in password):
        return "Medium", "Password needs an uppercase letter"
    elif not any(char in r"[!#\"$%&'()*+,\-./:;<=>?@[\]^_`{|}~]" for char in password):
        return "Medium", "Password needs a special character"
    return "Strong", "Good password"

def update_strength_meter(password: str, strength_label: tk.Label, progress: ttk.Progressbar) -> None:
    """Updates the password strength label and progress bar."""
    strength, reason = checkPasswordStrength(password)

    # Update the strength label
    strength_label.config(text=f"Strength: {strength} ({reason})")

    # Update the progress bar based on strength
    if strength == "Empty":
        progress['value'] = 0
        progress.config(style="danger.Horizontal.TProgressbar")
    elif strength == "Weak":
        progress['value'] = 33
        progress.config(style="danger.Horizontal.TProgressbar")
    elif strength == "Medium":
        progress['value'] = 66
        progress.config(style="warning.Horizontal.TProgressbar")
    elif strength == "Strong":
        progress['value'] = 100
        progress.config(style="success.Horizontal.TProgressbar")

def generate_password(length=12) -> str:
    """Generates a random password with specified length."""
    # Define the characters pool: uppercase, lowercase, digits, and punctuation
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    special_chars = string.punctuation
    digits = string.digits

    password = [random.choice(lowercase), random.choice(uppercase), random.choice(special_chars), random.choice(digits)]

    # Fill the rest of the characters with random characters
    all_chars = uppercase + special_chars + digits + lowercase
    for _ in range(length - 4):
       password.append(random.choice(all_chars))

    # Shuffle the list to avoid the first four characters always being in the same character set order
    random.shuffle(password)

    # Join the characters into a single string
    password = ''.join(password)
    return password

def generate_and_display_password(password_entry: tk.Entry, password_label: tk.Label, strength_label: tk.Label, progress: ttk.Progressbar, length=12) -> None:
    """Generates a password, displays it in the label and entry, and updates the strength meter."""
    generated_password = generate_password(length)
    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated_password)
    
    # Update the strength meter and label
    update_strength_meter(generated_password, strength_label, progress)
    
    # Display the generated password
    password_label.config(text=f"Generated Password: {generated_password}")
    
    return generated_password

def copy_password_to_clipboard(password: str) -> None:
    """Copies the generated password to the clipboard."""
    pyperclip.copy(password)  # Copy the password to clipboard
    messagebox.showinfo("Copied", "Password copied to clipboard!")

def setup_styles() -> None:
    """Sets up the styles for the progress bar."""
    style = ttk.Style()
    style.configure("danger.Horizontal.TProgressbar",
                    thickness=20, 
                    background="red")
    style.configure("warning.Horizontal.TProgressbar", 
                    thickness=20, 
                    background="yellow")
    style.configure("success.Horizontal.TProgressbar", 
                    thickness=20, 
                    background="green")
