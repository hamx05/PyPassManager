import os
import json
from config import USER_DB_FILE, CREDENTIALS_FILE, CURRENT_USER

def initializeStorage(username: str) -> None:
    """Initializes 'credentials.json' with a username:empty array pair, if it doesn't exist."""
    
    # Check if the credentials.json file exists
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as j:
            data = json.load(j)
    else:
        data = {}
    
    # Add the username with an empty array (if it doesn't already exist)
    if username not in data:
        data[username] = []

    # Write the updated data back into the file
    with open(CREDENTIALS_FILE, "w") as j:
        json.dump(data, j, indent=4)

def loadCredentials(username: str) -> list:
    """
    This function loads the credentials for a given username from the 'credentials.json' file.

    Args:
        username (str): The username for which to load the credentials.

    Returns:
        list: The list of credentials for the given username, or an empty list if the username is not found.
    """
    try:
        # Open the credentials.json file and load the data
        with open(CREDENTIALS_FILE, "r") as json_file:
            data = json.load(json_file)

        # Return the list of credentials for the given username, or an empty list if not found
        return data.get(username, [])
    
    except FileNotFoundError:
        print("*** ERROR: credentials.json file not found.")
        return []
    except json.JSONDecodeError:
        print("*** ERROR: Failed to decode JSON data.")
        return []

def saveCredentials(credentials_list) -> None:
    """
    This function saves the modified credentials list for the current user back to the JSON file.
    """
    current_user = CURRENT_USER.get()  # Get current user
    if not current_user:
        raise ValueError("No user is currently logged in")
    
    try:
        # Load the current credentials data from the JSON file
        with open(CREDENTIALS_FILE, "r") as json_file:
            credentials_data = json.load(json_file)

        # Check if the current user exists in the data
        if CURRENT_USER not in credentials_data:
            # If the user doesn't exist, initialize their credentials list
            credentials_data[current_user] = []

        # Update the credentials list for the current user
        credentials_data[current_user] = credentials_list

        # Save the updated data back to the file
        with open(CREDENTIALS_FILE, "w") as json_file:
            json.dump(credentials_data, json_file, indent=4)

    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: {e}")

def appendCredential(website: str, username: str, password: str, public_key: tuple[int], private_key: tuple[int]) -> None:
    """
    This function takes the new credential details as input, creates a new dictionary/object, appends it to the list, and saves the updated list.
    """
    current_user = CURRENT_USER.get()  # Get current user
    if not current_user:
        raise ValueError("No user is currently logged in")

    encryption_key = public_key[0]
    decryption_key = private_key[0]
    modulusN = public_key[1]

    credentials_list = loadCredentials(current_user)
    new_credential = {
        "website": website,
        "username": username,
        "password": password,
        "publickey": encryption_key,
        "privatekey": decryption_key,
        "modulus": modulusN
    }
    credentials_list.append(new_credential)
    saveCredentials(credentials_list)

def deleteCredential(index) -> None:
    """
    This function takes the index of the credential to be deleted, removes it from the list, and saves the updated list.
    """
    current_user = CURRENT_USER.get()  # Get current user
    if not current_user:
        raise ValueError("No user is currently logged in")
    
    credentialsList = loadCredentials(current_user)
    del credentialsList[index]
    saveCredentials(credentialsList)