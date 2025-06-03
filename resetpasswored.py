import tkinter as tk
import sqlite3
import subprocess
from argon2 import PasswordHasher
import re
from datetime import datetime, timedelta
import sys


# Modern color scheme
COLORS = {
    'primary': '#3498db',      # Blue
    'secondary': '#2ecc71',    # Green
    'bg': '#2C3E50',          # Dark background
    'input_bg': '#34495E',     # Input background
    'text': '#FFFFFF',         # White text
    'error': '#E74C3C',        # Error red
    'success': '#2ecc71',      # Success green
    'hover': '#2980b9'         # Hover blue
}

# إضافة ثوابت للتأخير الزمني
RESET_DELAY = 5  # ثواني
MAX_RESET_ATTEMPTS = 3
reset_attempts = {}

# Database connection
db = sqlite3.connect("user.db")
cursor = db.cursor()

# Initialize password hasher
ph = PasswordHasher()

# Create users table if not exists
cursor.execute('''CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    security_question TEXT NOT NULL,
    security_answer TEXT NOT NULL)''')

# Create reset attempts table
cursor.execute('''CREATE TABLE IF NOT EXISTS reset_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    attempt_time TIMESTAMP,
    success BOOLEAN)''')
db.commit()

def check_reset_attempts(username):
    """التحقق من محاولات إعادة تعيين كلمة المرور"""
    current_time = datetime.now()
    
    if username in reset_attempts:
        last_attempt = reset_attempts[username]['last_attempt']
        if (current_time - last_attempt) < timedelta(seconds=RESET_DELAY):
            return False
        if reset_attempts[username]['count'] >= MAX_RESET_ATTEMPTS:
            return False
    return True

def update_reset_attempts(username, success):
    """تحديث محاولات إعادة تعيين كلمة المرور"""
    current_time = datetime.now()
    
    if username not in reset_attempts:
        reset_attempts[username] = {'count': 0, 'last_attempt': current_time}
    
    reset_attempts[username]['count'] += 1
    reset_attempts[username]['last_attempt'] = current_time
    
    # تسجيل المحاولة في قاعدة البيانات
    cursor.execute("""
        INSERT INTO reset_attempts (username, attempt_time, success)
        VALUES (?, ?, ?)
    """, (username, current_time, success))
    db.commit()

def validate_input(char):
    # Prevent Arabic characters, allow only English letters, numbers, and basic punctuation
    return bool(re.match(r'^[a-zA-Z0-9@#$%^&*()_+=\-\[\]{}|\\:;"\'<>,.?/~` ]*$', char) if char else True)

def verify_security_answer(username, answer):
    cursor.execute("SELECT security_answer FROM user WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        stored_answer = result[0]
        try:
            ph.verify(stored_answer, answer.lower().encode())
            return True
        except:
            return False
    return False

def get_security_question(username):
    cursor.execute("SELECT security_question FROM user WHERE username = ?", (username,))
    result = cursor.fetchone()
    return result[0] if result else None

def show_error(error_label, message="Incorrect entry"):
    try:
        if error_label.winfo_exists():
            error_label.config(text=message)
            root.after(2000, lambda: error_label.config(text="") if error_label.winfo_exists() else None)
    except tk.TclError:
        # Create a new error label if the old one was destroyed
        new_error_label = tk.Label(
            frame,
            text=message,
            font=("Arial", 12),
            bg=COLORS['input_bg'],
            fg=COLORS['error']
        )
        new_error_label.pack(pady=(0, 20))
        root.after(2000, lambda: new_error_label.config(text="") if new_error_label.winfo_exists() else None)
        return new_error_label
    return error_label

def toggle_password_visibility(entry_widget, button):
    if entry_widget.cget('show') == '*':
        entry_widget.config(show='')
        button.config(text='🔒')
    else:
        entry_widget.config(show='*')
        button.config(text='👁')

def update_password(username, new_password_entry, confirm_password_entry, error_label):
    new_password = new_password_entry.get()
    confirm_password = confirm_password_entry.get()

    if new_password != confirm_password:
        show_error(error_label, "كلمة المرور غير متطابقة")
        new_password_entry.delete(0, tk.END)
        confirm_password_entry.delete(0, tk.END)
        new_password_entry.focus()
        return

    if len(new_password) < 8:
        show_error(error_label, "كلمة المرور ضعيفة - يجب أن تكون 8 أحرف على الأقل")
        new_password_entry.delete(0, tk.END)
        confirm_password_entry.delete(0, tk.END)
        new_password_entry.focus()
        return

    # Hash and update the new password
    try:
        password_hash = ph.hash(new_password.encode())
        cursor.execute("UPDATE user SET password = ? WHERE username = ?", 
                      (password_hash, username))
        db.commit()
        
        # Show success message and close window
        success_label = tk.Label(frame, text="Password updated successfully!", 
                               font=("Arial", 12), bg=COLORS['input_bg'], 
                               fg=COLORS['success'])
        success_label.pack(pady=10)
        
        # Close window and open login after delay
        root.after(2000, lambda: [root.destroy(), subprocess.Popen([sys.executable, "login.py"])])
    except Exception as e:
        show_error(error_label, "حدث خطأ أثناء تحديث كلمة المرور")
        new_password_entry.delete(0, tk.END)
        confirm_password_entry.delete(0, tk.END)
        new_password_entry.focus()

def show_new_password_form(frame, username, error_label):
    for widget in frame.winfo_children():
        widget.destroy()

    tk.Label(frame, text="New Password:", font=("Arial", 12, "bold"), 
            bg=COLORS['input_bg'], fg=COLORS['text']).pack(pady=5)
    
    # Password entry frame
    password_frame = tk.Frame(frame, bg=COLORS['input_bg'])
    password_frame.pack(pady=5)
    
    new_password_entry = tk.Entry(password_frame, show="*", width=40, font=("Arial", 12),
                                  bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'])
    new_password_entry.config(validate="key", validatecommand=(root.register(validate_input), '%S'))
    new_password_entry.pack(side=tk.LEFT, padx=5)
    
    eye_button = tk.Button(password_frame, text="👁", bg=COLORS['primary'], fg=COLORS['text'],
                          command=lambda: toggle_password_visibility(new_password_entry, eye_button))
    eye_button.pack(side=tk.LEFT)

    tk.Label(frame, text="Confirm Password:", font=("Arial", 12, "bold"), 
            bg=COLORS['input_bg'], fg=COLORS['text']).pack(pady=5)
    
    # Confirm password frame
    confirm_frame = tk.Frame(frame, bg=COLORS['input_bg'])
    confirm_frame.pack(pady=5)
    
    confirm_password_entry = tk.Entry(confirm_frame, show="*", width=40, font=("Arial", 12),
                                      bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'])
    confirm_password_entry.config(validate="key", validatecommand=(root.register(validate_input), '%S'))
    confirm_password_entry.pack(side=tk.LEFT, padx=5)
    
    eye_button2 = tk.Button(confirm_frame, text="👁", bg=COLORS['primary'], fg=COLORS['text'],
                           command=lambda: toggle_password_visibility(confirm_password_entry, eye_button2))
    eye_button2.pack(side=tk.LEFT)

    # Enter key bindings
    new_password_entry.bind('<Return>', lambda e: confirm_password_entry.focus())
    confirm_password_entry.bind('<Return>', 
                              lambda e: update_password(username, new_password_entry, 
                                                      confirm_password_entry, error_label))

    update_btn = tk.Button(frame, text="Update Password", 
                          command=lambda: update_password(username, new_password_entry, 
                                                        confirm_password_entry, error_label),
                          bg=COLORS['success'], fg=COLORS['text'], font=("Arial", 12, "bold"))
    update_btn.pack(pady=10)

def verify_answer(username, answer_entry, frame, error_label):
    answer = answer_entry.get().strip()
    if verify_security_answer(username, answer):
        show_new_password_form(frame, username, error_label)
    else:
        answer_entry.delete(0, tk.END)
        answer_entry.focus()
        show_error(error_label, "Incorrect security answer")

def verify_username(username_entry, frame, error_label):
    username = username_entry.get().strip()
    
    if not check_reset_attempts(username):
        show_error(error_label, "Too many attempts. Please wait before trying again.")
        return
        
    security_question = get_security_question(username)
    
    if security_question:
        update_reset_attempts(username, True)
        for widget in frame.winfo_children():
            widget.destroy()

        tk.Label(frame, text="Security Question:", font=("Arial", 12, "bold"), 
                bg=COLORS['input_bg'], fg=COLORS['text']).pack(pady=5)
        tk.Label(frame, text=security_question, font=("Arial", 12), 
                bg=COLORS['input_bg'], fg=COLORS['text']).pack(pady=5)
        
        tk.Label(frame, text="Answer:", font=("Arial", 12, "bold"), 
                bg=COLORS['input_bg'], fg=COLORS['text']).pack(pady=5)
        answer_entry = tk.Entry(frame, width=40, font=("Arial", 12),
                              bg=COLORS['bg'], fg=COLORS['text'], insertbackground=COLORS['text'])
        answer_entry.config(validate="key", validatecommand=(root.register(validate_input), '%S'))
        answer_entry.pack(pady=5)

        verify_answer_btn = tk.Button(frame, text="Verify Answer", 
                                    command=lambda: verify_answer(username, answer_entry, frame, error_label),
                                    bg=COLORS['primary'], fg=COLORS['text'], font=("Arial", 12, "bold"))
        verify_answer_btn.pack(pady=10)
        
        answer_entry.bind('<Return>', lambda e: verify_answer(username, answer_entry, frame, error_label))
        answer_entry.focus()
    else:
        update_reset_attempts(username, False)
        username_entry.delete(0, tk.END)
        username_entry.focus()
        show_error(error_label, "Username not found")

# Main window setup
root = tk.Tk()
root.title("Password Reset")

# Center window on screen
window_width = 500
window_height = 400
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2
root.geometry(f"{window_width}x{window_height}+{x}+{y}")

root.configure(bg=COLORS['bg'])
root.iconbitmap("icono.ico")
# Create main container
main_container = tk.Frame(root, bg=COLORS['bg'])
main_container.pack(expand=True, fill='both', padx=40, pady=20)

# Header
header_label = tk.Label(
    main_container,
    text="Reset Password",
    font=("Arial", 24, "bold"),
    bg=COLORS['bg'],
    fg=COLORS['text']
)
header_label.pack(pady=(0, 30))

# Create main frame
frame = tk.Frame(main_container, bg=COLORS['input_bg'], padx=30, pady=30)
frame.pack(expand=True, fill='both')

# Username entry with modern styling
username_label = tk.Label(
    frame,
    text="Username:",
    font=("Arial", 12, "bold"),
    bg=COLORS['input_bg'],
    fg=COLORS['text']
)
username_label.pack(anchor='w', pady=(0, 5))

username_entry = tk.Entry(
    frame,
    width=40,
    font=("Arial", 12),
    bg=COLORS['bg'],
    fg=COLORS['text'],
    insertbackground=COLORS['text'],
    relief='flat',
    validate="key",
    validatecommand=(root.register(validate_input), '%S')
)
username_entry.pack(fill='x', pady=(0, 20))

# Error label with modern styling
error_label = tk.Label(
    frame,
    text="",
    font=("Arial", 12),
    bg=COLORS['input_bg'],
    fg=COLORS['error']
)
error_label.pack(pady=(0, 20))

# Verify Username Button with modern styling
verify_button = tk.Button(
    frame,
    text="Verify Username",
    font=("Arial", 12, "bold"),
    bg=COLORS['primary'],
    fg=COLORS['text'],
    padx=20,
    pady=10,
    relief='flat',
    cursor="hand2",
    command=lambda: verify_username(username_entry, frame, error_label)
)
verify_button.pack(fill='x', pady=(0, 20))

# Add hover effects
def on_enter(e):
    e.widget['background'] = COLORS['hover']

def on_leave(e):
    e.widget['background'] = COLORS['primary']

verify_button.bind("<Enter>", on_enter)
verify_button.bind("<Leave>", on_leave)

# Enter key binding for username
username_entry.bind('<Return>', lambda e: verify_username(username_entry, frame, error_label))
username_entry.focus()

root.mainloop()
db.close()
