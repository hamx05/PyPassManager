import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from config import USER_DB_FILE
from utils import ifUsersExist, setup_styles
from gui import (
    setup_user, validate_user, logout, add_credential, view_credentials, 
    delete_credential, center_window, WINDOW_WIDTH, WINDOW_HEIGHT, 
    BG_COLOR, BUTTON_BG, BUTTON_FG, HEADER_BG, HEADER_FG, TEXT_COLOR, 
    ACCENT_COLOR, PADDING, create_button, add_credits
)

def show_main_interface(root) -> None:
    """Displays the main interface after user validation."""
    # Hide the root window
    root.withdraw()
    
    # Create main window
    main_window = tk.Toplevel(root)
    main_window.title("Password Manager")
    center_window(main_window, WINDOW_WIDTH, WINDOW_HEIGHT)
    main_window.protocol("WM_DELETE_WINDOW", lambda: logout(main_window, root))
    main_window.configure(bg=BG_COLOR)
    
    # Header
    header_frame = tk.Frame(main_window, bg=HEADER_BG, pady=10)
    header_frame.pack(fill=tk.X)
    
    header_label = tk.Label(header_frame, text="Password Manager", 
                           font=("Arial", 18, "bold"), bg=HEADER_BG, fg=HEADER_FG)
    header_label.pack(pady=20)
    
    # Content frame
    content_frame = tk.Frame(main_window, bg=BG_COLOR)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=PADDING, pady=PADDING)
    
    # Create a frame for buttons
    button_frame = tk.Frame(content_frame, bg=BG_COLOR)
    button_frame.pack(pady=20)
    
    # Add buttons with consistent width
    add_btn = create_button(button_frame, "Add Credential", add_credential)
    add_btn.pack(pady=5)
    
    view_btn = create_button(button_frame, "View Credentials", view_credentials)
    view_btn.pack(pady=5)
    
    delete_btn = create_button(button_frame, "Delete Credential", delete_credential)
    delete_btn.pack(pady=5)
    
    from analysis import analyzePasswords
    analyze_btn = create_button(
        button_frame, 
        "Analyze Passwords", 
        lambda: messagebox.showinfo("Password Analysis", analyzePasswords())
    )
    analyze_btn.pack(pady=5)
    
    # Add a separator
    separator = ttk.Separator(main_window, orient='horizontal')
    separator.pack(fill='x', padx=20, pady=10)
    
    # Bottom buttons frame - FIX: Make buttons consistent size
    bottom_frame = tk.Frame(main_window, bg=BG_COLOR)
    bottom_frame.pack(pady=10)
    
    # Bottom buttons
    logout_btn = create_button(bottom_frame, "Logout", lambda: logout(main_window, root), is_danger=True)
    logout_btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    exit_btn = create_button(bottom_frame, "Exit", root.quit, is_primary=False)
    exit_btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    # Add credits at the bottom
    add_credits(main_window)

def main():
    # Create the root window
    root = tk.Tk()
    root.title("Password Manager")
    center_window(root, WINDOW_WIDTH, WINDOW_HEIGHT)
    root.configure(bg=BG_COLOR)

    # Set up styles for progress bars
    setup_styles()
    
    # Create a frame for content
    content_frame = tk.Frame(root, bg=BG_COLOR)
    content_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
    
    # Add a header
    header_frame = tk.Frame(root, bg=HEADER_BG, pady=10)
    header_frame.pack(fill=tk.X)
    
    header_label = tk.Label(header_frame, text="Password Manager", 
                           font=("Arial", 18, "bold"), bg=HEADER_BG, fg=HEADER_FG)
    header_label.pack(pady=20)

    # Check if users exist in the USER_DB_FILE
    if not ifUsersExist(USER_DB_FILE):
        # No users found, ask the user to set up a new login
        message_label = tk.Label(content_frame, 
                                text="Welcome to Password Manager!\nNo users found. Please set up a new user.",
                                font=("Arial", 12), bg=BG_COLOR, fg=TEXT_COLOR)
        message_label.pack(pady=20)
        
        setup_btn = create_button(content_frame, "Set Up New User", lambda: setup_user(root), is_primary=True)
        setup_btn.pack(pady=10)
    else:
        # Users exist, prompt the user to log in or set up a new user
        message_label = tk.Label(content_frame, 
                                text="Welcome back to Password Manager!",
                                font=("Arial", 12), bg=BG_COLOR, fg=TEXT_COLOR)
        message_label.pack(pady=10)
        
        login_btn = create_button(
            content_frame, 
            "Log In", 
            lambda: validate_user(root, show_main_interface),
            is_primary=True
        )
        login_btn.pack(pady=5)
        
        setup_btn = create_button(content_frame, "Set Up New User", lambda: setup_user(root))
        setup_btn.pack(pady=5)
        
        # Add a separator
        separator = ttk.Separator(content_frame, orient='horizontal')
        separator.pack(fill='x', pady=10)
        
        exit_btn = create_button(content_frame, "Exit", root.quit, is_primary=False)
        exit_btn.pack(pady=5)
    
    # Add credits at the bottom
    add_credits(root)

    # Start the Tkinter event loop
    root.mainloop()

if __name__ == "__main__":
    main()