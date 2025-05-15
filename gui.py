import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.simpledialog import askstring
from config import CURRENT_USER
from crypto import md5
from database import add_credential, get_credentials, delete_credential, initialize_database
from utils import (
    validatePasskey, storeLoginCredentials, isUserValid, checkPasswordStrength,
    update_strength_meter, generate_and_display_password, copy_password_to_clipboard
)

# Defining constant main window sizes
WINDOW_WIDTH = 500
WINDOW_HEIGHT = 400
PADDING = 20
BUTTON_WIDTH = 20
ENTRY_WIDTH = 30

# sub-window sizes
SUB_WINDOW_WIDTH = 500
SUB_WINDOW_HEIGHT = 400

# Color scheme - using standard web colors for better compatibility
PRIMARY_COLOR = "#4a6fa5"  # Blue
SECONDARY_COLOR = "#e8f1f5"  # Light blue
ACCENT_COLOR = "#166088"  # Darker blue
TEXT_COLOR = "#333333"  # Dark gray
BG_COLOR = "#f5f5f5"  # Light gray
BUTTON_BG = PRIMARY_COLOR
BUTTON_FG = "white"
HEADER_BG = PRIMARY_COLOR
HEADER_FG = "white"

# Credits information
CREDITS = "Made by Muhammad Hammad"

def center_window(window, width, height):
    """Center a window on the screen and set minimum size."""
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")
    # Set minimum size to prevent UI elements from being cut off
    window.minsize(width, height)
    # Update the window to ensure proper rendering
    window.update_idletasks()

def create_form_field(parent, label_text, show=None, width=ENTRY_WIDTH):
    """Create a standardized form field with label and entry."""
    frame = tk.Frame(parent, bg=BG_COLOR)
    frame.pack(fill=tk.X, padx=PADDING, pady=5)
    
    label = tk.Label(frame, text=label_text, width=15, anchor="w", 
                    bg=BG_COLOR, fg=TEXT_COLOR, font=("Arial", 10))
    label.pack(side=tk.LEFT)
    
    entry = tk.Entry(frame, show=show, width=width, font=("Arial", 10),
                    bg="white", fg=TEXT_COLOR, relief="solid", bd=1)
    entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
    
    return entry

def create_button(parent, text, command, is_primary=False, is_danger=False):
    """Create a standardized button with consistent styling."""
    if is_danger:
        bg_color = "#e74c3c"  # Red for dangerous actions
        active_bg = "#c0392b"  # Darker red for hover
    elif not is_primary:
        bg_color = "#7f8c8d"  # Gray for secondary actions
        active_bg = "#2c3e50"  # Darker gray for hover
    else:
        bg_color = BUTTON_BG
        active_bg = ACCENT_COLOR
        
    button = tk.Button(
        parent, 
        text=text,
        command=command,
        width=BUTTON_WIDTH,
        bg=bg_color,
        fg=BUTTON_FG,
        font=("Arial", 10, "bold" if is_primary else "normal"),
        relief="flat",
        activebackground=active_bg,
        activeforeground="white",
        padx=10,
        pady=5
    )
    
    return button

def add_credits(parent):
    """Add credits at the bottom of the window."""
    credits_frame = tk.Frame(parent, bg=BG_COLOR)
    credits_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
    
    credits_label = tk.Label(
        credits_frame, 
        text=CREDITS, 
        bg=BG_COLOR, 
        fg="#888888",  # Light gray for subtle appearance
        font=("Arial", 8, "italic")
    )
    credits_label.pack(side=tk.RIGHT, padx=10)

def setup_user(root) -> None:
    """Handles user setup through the GUI."""
    user_window = tk.Toplevel(root)
    user_window.title("Set Up User")
    user_window.transient(root)
    user_window.grab_set()
    center_window(user_window, SUB_WINDOW_WIDTH, SUB_WINDOW_HEIGHT+50)
    user_window.configure(bg=BG_COLOR)
    
    # Header
    header_frame = tk.Frame(user_window, bg=HEADER_BG, pady=10)
    header_frame.pack(fill=tk.X)
    
    header_label = tk.Label(header_frame, text="Create New User", 
                           font=("Arial", 16, "bold"), bg=HEADER_BG, fg=HEADER_FG)
    header_label.pack(pady=(PADDING, 10))
    
    # Content frame
    content_frame = tk.Frame(user_window, bg=BG_COLOR)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=PADDING, pady=PADDING)
    
    # Username field
    username_entry = create_form_field(content_frame, "Username:")
    
    # Password field
    password_frame = tk.Frame(content_frame, bg=BG_COLOR)
    password_frame.pack(fill=tk.X, padx=PADDING, pady=5)
    
    password_label = tk.Label(password_frame, text="Password:", width=15, anchor="w",
                             bg=BG_COLOR, fg=TEXT_COLOR, font=("Arial", 10))
    password_label.pack(side=tk.LEFT)
    
    password_entry = tk.Entry(password_frame, show="*", width=ENTRY_WIDTH, 
                             font=("Arial", 10), bg="white", fg=TEXT_COLOR, 
                             relief="solid", bd=1)
    password_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
    
    # Generated password display
    generated_frame = tk.Frame(content_frame, bg=BG_COLOR)
    generated_frame.pack(fill=tk.X, padx=PADDING, pady=5)
    
    password_display = tk.Label(content_frame, text="Generated Password: Not generated yet",
                               bg=BG_COLOR, fg=TEXT_COLOR, font=("Arial", 10))
    password_display.pack(padx=PADDING, pady=5)
    
    # Strength meter
    strength_frame = tk.Frame(content_frame, bg=BG_COLOR)
    strength_frame.pack(fill=tk.X, padx=PADDING, pady=5)
    
    strength_label = tk.Label(strength_frame, text="Strength: Not checked", width=30, anchor="w",
                             bg=BG_COLOR, fg=TEXT_COLOR, font=("Arial", 10))
    strength_label.pack(side=tk.LEFT)
    
    progress = ttk.Progressbar(strength_frame, style="danger.Horizontal.TProgressbar", 
                              length=200, mode='determinate')
    progress.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(10, 0))
        
    # Generate password button
    def generate_password_and_display():
        generated_password = generate_and_display_password(password_entry, password_display, strength_label, progress)
        return generated_password

    # Buttons frame
    button_frame = tk.Frame(content_frame, bg=BG_COLOR)
    button_frame.pack(fill=tk.X, padx=PADDING, pady=PADDING)

    # Create another frame inside for centered buttons
    center_frame = tk.Frame(button_frame, bg=BG_COLOR)
    center_frame.pack(expand=True)  # This centers the inner frame

    generate_button = create_button(center_frame, "Generate Password", generate_password_and_display)
    generate_button.pack(side=tk.LEFT, padx=5)

    # Copy password button
    def copy_password():
        password = password_entry.get()
        copy_password_to_clipboard(password)

    copy_button = create_button(center_frame, "Copy Password", copy_password)
    copy_button.pack(side=tk.LEFT, padx=5)

    # Update strength meter on password change
    def on_password_change(*args):
        password = password_entry.get()
        update_strength_meter(password, strength_label, progress)

    password_entry.bind("<KeyRelease>", on_password_change)

    # Submit the user data
    def validate_and_store_user():
        username = username_entry.get()
        password = password_entry.get()
        
        if not username:
            messagebox.showerror("Error", "Username is required.")
            return
            
        # Validate password strength
        is_valid, reason = validatePasskey(password)
        
        if not is_valid:
            messagebox.showerror("Error", reason)
            return
        
        try:
            # We're now passing the raw password to add_user
            from database import add_user
            add_user(username, password)
            messagebox.showinfo("Setup Complete", "User setup successfully. You can now log in.")
            user_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set up user: {e}")

    # 'Submit' button to submit the credentials
    submit_frame = tk.Frame(content_frame, bg=BG_COLOR)
    submit_frame.pack(fill=tk.X, padx=PADDING, pady=(0, PADDING))
    
    # Button container for side-by-side buttons
    button_container = tk.Frame(submit_frame, bg=BG_COLOR)
    button_container.pack(pady=10)
    
    submit_button = create_button(button_container, "Create User", validate_and_store_user, is_primary=True)
    submit_button.pack(side=tk.LEFT, padx=5)
    
    # Cancel button
    cancel_button = create_button(button_container, "Cancel", user_window.destroy, is_primary=False)
    cancel_button.pack(side=tk.LEFT, padx=5)
    
    # Add credits
    add_credits(user_window)

def validate_user(root, show_main_interface) -> None:
    """Handles user validation through the GUI with a single form."""
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.transient(root)
    login_window.grab_set()
    center_window(login_window, SUB_WINDOW_WIDTH, SUB_WINDOW_HEIGHT)
    login_window.configure(bg=BG_COLOR)
    
    # Header
    header_frame = tk.Frame(login_window, bg=HEADER_BG, pady=10)
    header_frame.pack(fill=tk.X)
    
    header_label = tk.Label(header_frame, text="Login to Password Manager", 
                           font=("Arial", 14, "bold"), bg=HEADER_BG, fg=HEADER_FG)
    header_label.pack(pady=(PADDING, 10))
    
    # Content frame
    content_frame = tk.Frame(login_window, bg=BG_COLOR)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=PADDING, pady=PADDING)
    
    # Username field
    username_entry = create_form_field(content_frame, "Username:")
    
    # Password field
    password_entry = create_form_field(content_frame, "Password:", show="*")
    
    def perform_login():
        username = username_entry.get()
        password = password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return
        
        if isUserValid(username, password):
            
            CURRENT_USER.set(username)
            login_window.destroy()
            messagebox.showinfo("Success", "Login successful!")
            show_main_interface(root)
            
            # Analyze passwords after successful login
            from analysis import analyzePasswords
            strength_summary = analyzePasswords()
            if strength_summary:
                messagebox.showinfo("Password Analysis", strength_summary)
        else:
            messagebox.showerror("Error", "Invalid username or password.")
    
    # Login button - FIX: Make it full width like other buttons
    button_frame = tk.Frame(content_frame, bg=BG_COLOR)
    button_frame.pack(fill=tk.X, padx=PADDING, pady=PADDING)
    
    # Button container for side-by-side buttons
    button_container = tk.Frame(button_frame, bg=BG_COLOR)
    button_container.pack(pady=10)
    
    login_button = create_button(button_container, "Login", perform_login, is_primary=True)
    login_button.pack(side=tk.LEFT, padx=5)
    
    # Cancel button
    cancel_button = create_button(button_container, "Cancel", login_window.destroy, is_primary=False)
    cancel_button.pack(side=tk.LEFT, padx=5)
    
    # Bind Enter key to login
    login_window.bind("<Return>", lambda event: perform_login())
    
    # Add credits
    add_credits(login_window)

def logout(main_window: tk.Toplevel, root: tk.Tk) -> None:
    """Logs out the current user and returns to the login/setup screen."""
    
    CURRENT_USER.set("None")  # Reset the current user
    CURRENT_USER.set_key(None)  # Reset the encryption key
    main_window.destroy()  # Close the main interface window
    root.deiconify()  # Redisplay the root login/setup window

def add_credential_window() -> None:
    """Adds a new credential with password strength meter."""
    # Open a new window to add credentials
    credential_window = tk.Toplevel()
    credential_window.title("Add Credential")
    # Use the standard sub-window size
    center_window(credential_window, SUB_WINDOW_WIDTH, SUB_WINDOW_HEIGHT + 120)
    credential_window.configure(bg=BG_COLOR)
    
    # Header
    header_frame = tk.Frame(credential_window, bg=HEADER_BG, pady=10)
    header_frame.pack(fill=tk.X)
    
    header_label = tk.Label(header_frame, text="Add New Credential", 
                           font=("Arial", 14, "bold"), bg=HEADER_BG, fg=HEADER_FG)
    header_label.pack(pady=(PADDING, 10))

    # Content frame
    content_frame = tk.Frame(credential_window, bg=BG_COLOR)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=PADDING, pady=PADDING)

    # Fields to input the website, username, and password
    website_entry = create_form_field(content_frame, "Website:")
    username_entry = create_form_field(content_frame, "Username:")
    password_entry = create_form_field(content_frame, "Password:", show="*")

    # Strength meter
    strength_frame = tk.Frame(content_frame, bg=BG_COLOR)
    strength_frame.pack(fill=tk.X, padx=PADDING, pady=5)
    
    strength_label = tk.Label(strength_frame, text="Strength: Not checked", width=30, anchor="w",
                             bg=BG_COLOR, fg=TEXT_COLOR, font=("Arial", 10))
    strength_label.pack(side=tk.LEFT)
    
    progress = ttk.Progressbar(strength_frame, style="danger.Horizontal.TProgressbar", length=200, mode='determinate')
    progress.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(10, 0))

    # Function to update password strength meter
    def on_password_change(*args):
        password = password_entry.get()
        update_strength_meter(password, strength_label, progress)

    password_entry.bind("<KeyRelease>", on_password_change)
    
    def submit_credential():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        # Check if any field is empty
        if not website or not username or not password:
            messagebox.showerror("Error", "All fields are required.")
            return
        
        # Validate password strength
        strength, reason = checkPasswordStrength(password)
        summary = strength + " Password! " +  reason
        messagebox.showinfo("Password Analysis", summary)

        try:
            # Store the credential using the new database function
            add_credential(website, username, password)
            messagebox.showinfo("Success", "Credential added successfully!")
            credential_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add credential: {e}")

    # Submit button
    submit_frame = tk.Frame(content_frame, bg=BG_COLOR)
    submit_frame.pack(fill=tk.X, padx=PADDING, pady=(0, PADDING))
    
    # Button container for side-by-side buttons
    button_container = tk.Frame(submit_frame, bg=BG_COLOR)
    button_container.pack(pady=10)
    
    submit_button = create_button(button_container, "Add Credential", submit_credential, is_primary=True)
    submit_button.pack(side=tk.LEFT, padx=5)
    
    # Cancel button
    cancel_button = create_button(button_container, "Cancel", credential_window.destroy, is_primary=False)
    cancel_button.pack(side=tk.LEFT, padx=5)
    
    # Add credits
    add_credits(credential_window)

def view_credentials() -> None:
    """Displays all saved credentials with search functionality."""
    credentials_window = tk.Toplevel()
    credentials_window.title("View Credentials")
    center_window(credentials_window, SUB_WINDOW_WIDTH, SUB_WINDOW_HEIGHT + 120)
    credentials_window.configure(bg=BG_COLOR)
    
    # Header
    header_frame = tk.Frame(credentials_window, bg=HEADER_BG, pady=10)
    header_frame.pack(fill=tk.X)
    
    header_label = tk.Label(header_frame, text="Your Saved Credentials", 
                           font=("Arial", 14, "bold"), bg=HEADER_BG, fg=HEADER_FG)
    header_label.pack(pady=(PADDING, 10))
    
    # Content frame
    content_frame = tk.Frame(credentials_window, bg=BG_COLOR)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=PADDING, pady=PADDING)
    
    # Search frame
    search_frame = tk.Frame(content_frame, bg=BG_COLOR)
    search_frame.pack(fill=tk.X, padx=PADDING, pady=5)
    
    search_label = tk.Label(search_frame, text="Search:", width=10, anchor="w",
                           bg=BG_COLOR, fg=TEXT_COLOR, font=("Arial", 10))
    search_label.pack(side=tk.LEFT)
    
    search_entry = tk.Entry(search_frame, width=ENTRY_WIDTH, font=("Arial", 10),
                           bg="white", fg=TEXT_COLOR, relief="solid", bd=1)
    search_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
    
    # Results frame with scrollbar
    results_frame = tk.Frame(content_frame, bg=BG_COLOR)
    results_frame.pack(fill=tk.BOTH, expand=True, padx=PADDING, pady=10)
    
    # Add scrollbar
    scrollbar = tk.Scrollbar(results_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Use Text widget instead of Label for better scrolling
    credentials_text = tk.Text(results_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, 
                              height=15, width=50, font=("Arial", 10),
                              bg="white", fg=TEXT_COLOR, relief="solid", bd=1)
    credentials_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=credentials_text.yview)
    
    def search_credentials():
        """Filters and displays credentials based on the search query."""
        query = search_entry.get().lower()
        credentials_text.delete(1.0, tk.END)  # Clear previous results
        
        try:
            # Get credentials from the database, filtered by search term if provided
            credentials = get_credentials(query if query else None)
            
            if not credentials:
                credentials_text.insert(tk.END, "No credentials found.")
                return
                
            # Display credentials with index numbers
            for i, cred in enumerate(credentials, 1):
                # Apply tags for styling
                credentials_text.insert(tk.END, f"{i}. Website: ", "index")
                credentials_text.insert(tk.END, f"{cred['website']}\n", "website")
                
                credentials_text.insert(tk.END, f"   Username: ", "label")
                credentials_text.insert(tk.END, f"{cred['username']}\n", "value")
                
                credentials_text.insert(tk.END, f"   Password: ", "label")
                credentials_text.insert(tk.END, f"{cred['password']}\n\n", "value")
            
            # Configure tags
            credentials_text.tag_configure("index", font=("Arial", 10, "bold"), foreground=PRIMARY_COLOR)
            credentials_text.tag_configure("website", font=("Arial", 10, "bold"))
            credentials_text.tag_configure("label", font=("Arial", 10), foreground=TEXT_COLOR)
            credentials_text.tag_configure("value", font=("Arial", 10))
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load credentials: {e}")
    
    # Search button
    search_button = create_button(search_frame, "Search", search_credentials)
    search_button.config(width=10)  # Override width for this specific button
    search_button.pack(side=tk.LEFT, padx=(10, 0))
    
    # Bind the search functionality to the key release event for dynamic search
    search_entry.bind("<KeyRelease>", lambda event: search_credentials())
    
    # Load and display all credentials initially
    search_credentials()
    
    # Close button
    button_frame = tk.Frame(credentials_window, bg=BG_COLOR)
    button_frame.pack(fill=tk.X, padx=PADDING, pady=10)
    
    close_button = create_button(button_frame, "Close", credentials_window.destroy)
    close_button.pack(pady=10)
    
    # Add credits
    add_credits(credentials_window)

def delete_credential_window() -> None:
    """Deletes a credential by ID with improved UI."""
    delete_window = tk.Toplevel()
    delete_window.title("Delete Credential")    
    # Use the standard sub-window size
    center_window(delete_window, SUB_WINDOW_WIDTH, SUB_WINDOW_HEIGHT + 120)
    delete_window.configure(bg=BG_COLOR)
    
    # Header
    header_frame = tk.Frame(delete_window, bg=HEADER_BG, pady=10)
    header_frame.pack(fill=tk.X)
    
    header_label = tk.Label(header_frame, text="Delete Credential", 
                           font=("Arial", 14, "bold"), bg=HEADER_BG, fg=HEADER_FG)
    header_label.pack(pady=(PADDING, 10))
    
    # Content frame
    content_frame = tk.Frame(delete_window, bg=BG_COLOR)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=PADDING, pady=PADDING)
    
    # Instructions
    instructions = tk.Label(content_frame, 
                           text="Enter the index number of the credential to delete.\nYou can view the index numbers in the View Credentials screen.",
                           bg=BG_COLOR, fg=TEXT_COLOR, font=("Arial", 10))
    instructions.pack(padx=PADDING, pady=5)
    
    # Index entry
    index_frame = tk.Frame(content_frame, bg=BG_COLOR)
    index_frame.pack(fill=tk.X, padx=PADDING, pady=10)
    
    index_label = tk.Label(index_frame, text="Credential Index:", width=15, anchor="w",
                          bg=BG_COLOR, fg=TEXT_COLOR, font=("Arial", 10))
    index_label.pack(side=tk.LEFT)
    
    index_entry = tk.Entry(index_frame, width=10, font=("Arial", 10),
                          bg="white", fg=TEXT_COLOR, relief="solid", bd=1)
    index_entry.pack(side=tk.LEFT)
    
    def perform_delete():
        try:
            index = int(index_entry.get())
            
            # Get all credentials to find the one with the given index
            credentials = get_credentials()
            
            if not credentials:
                messagebox.showinfo("No Credentials", "No credentials to delete.")
                return
                
            if index < 1 or index > len(credentials):
                raise IndexError("Index out of range")
                
            # Get the credential at the specified index (1-based to 0-based)
            cred = credentials[index - 1]
            website = cred['website']
            username = cred['username']
            
            confirm = messagebox.askyesno("Confirm Deletion", 
                                         f"Are you sure you want to delete:\n\nWebsite: {website}\nUsername: {username}")
            
            if confirm:
                # Delete the credential using its database ID
                delete_credential(cred['id'])
                messagebox.showinfo("Success", "Credential deleted successfully.")
                delete_window.destroy()
                
        except ValueError:
            messagebox.showerror("Error", "Invalid input. Enter a numeric index.")
        except IndexError:
            messagebox.showerror("Error", "Invalid index. Please select a valid credential.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    
    # Button frame
    button_frame = tk.Frame(content_frame, bg=BG_COLOR)
    button_frame.pack(fill=tk.X, padx=PADDING, pady=10)
    
    # Delete button
    delete_button = create_button(button_frame, "Delete Credential", perform_delete, is_primary=True, is_danger=True)
    delete_button.pack(pady=10)
    
    # View credentials button to help user find the index - FIX: Make it consistent width
    view_button = create_button(button_frame, "View Credentials", view_credentials)
    view_button.pack(pady=5)
    
    # Cancel button
    cancel_button = create_button(button_frame, "Cancel", delete_window.destroy, is_primary=False)
    cancel_button.pack(pady=5)
    
    # Add credits
    add_credits(delete_window)

# Initialize the database when the module is imported
initialize_database()