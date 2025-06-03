import tkinter as tk
import subprocess
import customtkinter as ctk
from argon2 import PasswordHasher
import sqlite3
import re
import time
import sqlite3 as sqlite
from datetime import datetime
import sys


# الإعدادات
ctk.set_appearance_mode("System")

# Simplified color scheme
COLORS = {
    'primary': '#3498db',      # Blue
    'bg': '#2C3E50',           # Dark background
    'input_bg': '#34495E',     # Input background
    'text': '#FFFFFF',         # White text
    'error': '#E74C3C'         # Error red
}

# Security questions list
SECURITY_QUESTIONS = [
    "What is your mother's maiden name?",
    "What was your first pet's name?",
    "What city were you born in?",
    "What is your favorite book?",
    "What was your childhood nickname?"
]

COMMON_PASSWORDS = {
    '123456', 'password', '123456789', 'qwerty',
    '111111', '123123', 'letmein', 'abc123',
    '12345678', 'admin', '1234', 'iloveyou',
    '12345', 'welcome', 'monkey', 'dragon',
    'football', 'baseball', 'master', 'shadow',
    '654321', 'superman', 'qwertyuiop', 'passw0rd',
    'zaq1zaq1', 'starwars', 'hello123', 'trustno1',
    '000000', '1q2w3e4r', 'sunshine', 'batman'

}

MAX_ATTEMPTS = 3  # الحد الأقصى للمحاولات
attempt_counter = {"register": 0, "login": 0}   # إضافة للمحاولات عند الدخول

ph = PasswordHasher(
    time_cost=6,
    memory_cost=131072, # 128MB
    parallelism=4
)

# القواميس للغات
TEXTS = {
    'en': {
        'header': "Create Account",
        'username_placeholder': "Username",
        'password_placeholder': "Password",
        'confirm_password_placeholder': "Confirm Password",
        'security_answer_placeholder': "Security Answer",
        'register_button': "Create Account",
        'login_link': "Already have an account? Login",
        'error_message': "Failed to register",
        'too_many_attempts': "Too many attempts. Please try again later.",
        'language': "Language"
    },
    'ar': {
        'header': "إنشاء حساب",
        'username_placeholder': "اسم المستخدم",
        'password_placeholder': "كلمة المرور",
        'confirm_password_placeholder': "تأكيد كلمة المرور",
        'security_answer_placeholder': "إجابة الأمان",
        'register_button': "إنشاء حساب",
        'login_link': "هل لديك حساب؟ تسجيل الدخول",
        'error_message': "فشل في التسجيل",
        'too_many_attempts': "عدد المحاولات كبير جدًا. حاول لاحقًا.",
        'language': "اللغة"
    }
}

current_language = 'en'

# إضافة حد أقصى لطول المدخلات
MAX_USERNAME_LENGTH = 50
MAX_PASSWORD_LENGTH = 128

# إضافة تأخير زمني بين المحاولات
LOGIN_DELAY = 2  # ثواني
RESET_DELAY = 5  # ثواني

def setup_database():
    try:
        conn = sqlite.connect("user.db")  # قاعدة بيانات مشفرة
        cursor = conn.cursor()
        
        cursor.execute("ATTACH DATABASE 'user.db' AS encrypted KEY 'encryption_key'")
        cursor.execute('''CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            security_question TEXT NOT NULL,
            security_answer TEXT NOT NULL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY,
            username TEXT,
            attempt_time TIMESTAMP,
            ip_address TEXT,
            success BOOLEAN
        )''')
        conn.commit()
        return conn, cursor
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None, None

def is_password_strong(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# تنظيف الإدخال
def clean_input(text):
    return re.sub(r"[^\w\s@.-]", "", text.strip())

def validate_text(char):
    if any(ord(c) in range(0x0600, 0x06FF + 1) or 
           ord(c) in range(0x0750, 0x077F + 1) or 
           ord(c) in range(0x08A0, 0x08FF + 1) 
           for c in char):
        return False
    return True

def validate_username(char):
    # Only allow English letters, numbers, and hyphen
    return bool(re.match(r'^[a-zA-Z0-9-]+$', char) if char else True)

def toggle_password_visibility(entry, button):
    if entry.cget('show') == '':
        entry.configure(show='•')
        button.configure(text="🔒")
    else:
        entry.configure(show='')
        button.configure(text="👁")

def create_entry(parent, placeholder, show=None, validate_func=None, is_password=False):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(pady=10)

    entry = ctk.CTkEntry(
        frame,
        placeholder_text=placeholder,
        font=("Arial", 14),
        height=40,
        width=250 if is_password else 300,
        show=show
    )
    entry.pack(side="left", expand=True, fill="x")

    if validate_func:
        validate_command = parent.register(validate_func)
        entry.configure(validate="key", validatecommand=(validate_command, '%S'))

    if is_password:
        eye_btn = ctk.CTkButton(
            frame,
            text="🔒",
            width=40,
            font=("Arial", 14),
            command=lambda: toggle_password_visibility(entry, eye_btn)
        )
        eye_btn.pack(side="right", padx=(5, 0))

    return entry

def show_error(error_label, message=None):
    msg = message or TEXTS[current_language]["error_message"]
    error_label.configure(text=msg, text_color=COLORS['error'])
    error_label.after(3000, lambda: error_label.configure(text=""))

def create_account(username_entry, password_entry, confirm_password_entry,
                  security_question_var, security_answer_entry, error_label, root, conn, cursor):
    global attempt_counter
    lang_texts = TEXTS[current_language]

    if attempt_counter["register"] >= MAX_ATTEMPTS:
        show_error(error_label, lang_texts["too_many_attempts"])
        time.sleep(1)
        root.destroy()
        return

    username = username_entry.get().strip().replace(" ", "")
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()
    security_question = security_question_var.get()
    security_answer = security_answer_entry.get().strip().lower()

    if not all([username, password, confirm_password, security_answer]):
        show_error(error_label)
        attempt_counter["register"] += 1
        return

    if password != confirm_password or not is_password_strong(password):
        show_error(error_label)
        password_entry.delete(0, 'end')
        confirm_password_entry.delete(0, 'end')
        password_entry.focus()
        attempt_counter["register"] += 1
        return

    try:
        password_hash = ph.hash(password.encode())
        answer_hash = ph.hash(security_answer.encode())

        if not conn or not cursor:
            conn, cursor = setup_database()

        cursor.execute(""" 
            INSERT INTO user (username, password, security_question, security_answer)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, security_question, answer_hash))
        conn.commit()

        root.destroy()
        subprocess.Popen([sys.executable, "login.py"])

    except sqlite.IntegrityError:
        show_error(error_label)
        username_entry.delete(0, 'end')
        username_entry.focus()
        attempt_counter["register"] += 1
    except Exception as e:
        show_error(error_label)
        print(f"Error: {e}")
        attempt_counter["register"] += 1

# تغيير اللغة
def change_language(choice):
    global current_language
    current_language = choice
    update_ui()

def update_ui():
    lang_menu.set(current_language)
    header_label.configure(text=TEXTS[current_language]['header'])
    username_entry.configure(placeholder_text=TEXTS[current_language]['username_placeholder'])
    password_entry.configure(placeholder_text=TEXTS[current_language]['password_placeholder'])
    confirm_password_entry.configure(placeholder_text=TEXTS[current_language]['confirm_password_placeholder'])
    security_answer_entry.configure(placeholder_text=TEXTS[current_language]['security_answer_placeholder'])
    register_btn.configure(text=TEXTS[current_language]['register_button'])
    login_label.configure(text=TEXTS[current_language]['login_link'])

def main():
    global lang_menu, header_label
    global username_entry, password_entry, confirm_password_entry, security_answer_entry
    global register_btn, login_label

    root = ctk.CTk()
    root.title("Register")
   
    width, height = 500, 700
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = int((screen_width / 2) - (width / 2))
    y = int((screen_height / 2) - (height / 2))
    root.geometry(f"{width}x{height}+{x}+{y}")
    root.configure(fg_color=COLORS['bg'])
    root.iconbitmap("icono.ico")
    # Setup database
    conn, cursor = setup_database()

    # شريط علوي للغة
    lang_menu = ctk.CTkOptionMenu(root, values=["en", "ar"], command=change_language, width=100)
    lang_menu.set(current_language)
    lang_menu.pack(pady=(10, 0), anchor="ne", padx=10)

    # Header (العنوان الوحيد المتبقي)
    header_label = ctk.CTkLabel(
        root,
        text=TEXTS[current_language]['header'],
        font=("Arial", 24, "bold"),
        text_color=COLORS['text']
    )
    header_label.pack(pady=30)

    # Error label
    error_label = ctk.CTkLabel(
        root,
        text="",
        text_color=COLORS['error'],
        font=("Arial", 12)
    )
    error_label.pack(pady=10)

    # Form fields with validation
    username_entry = create_entry(root, TEXTS[current_language]['username_placeholder'])
    password_entry = create_entry(root, TEXTS[current_language]['password_placeholder'], show="•", is_password=True)
    confirm_password_entry = create_entry(root, TEXTS[current_language]['confirm_password_placeholder'], show="•", is_password=True)

    # Security Question
    security_question_var = tk.StringVar(value=SECURITY_QUESTIONS[0])
    security_question_menu = ctk.CTkOptionMenu(root, values=SECURITY_QUESTIONS, variable=security_question_var, width=300)
    security_question_menu.pack(pady=10)

    security_answer_entry = create_entry(root, TEXTS[current_language]['security_answer_placeholder'])

    # Register Button
    register_btn = ctk.CTkButton(
        root, text=TEXTS[current_language]["register_button"], font=("Arial", 14, "bold"), width=300,
        command=lambda: create_account(
            username_entry, password_entry, confirm_password_entry,
            security_question_var, security_answer_entry, error_label,
            root, conn, cursor
        )
    )
    register_btn.pack(pady=20)

    # Login Link
    login_label = ctk.CTkLabel(root, text=TEXTS[current_language]['login_link'], font=("Arial", 12), text_color=COLORS['primary'], cursor="hand2")
    login_label.pack(pady=10)
    login_label.bind("<Button-1>", lambda e: [root.destroy(), subprocess.Popen([sys.executable, "login.py"])])

    # Add Enter key bindings
    username_entry.bind('<Return>', lambda e: password_entry.focus())
    password_entry.bind('<Return>', lambda e: confirm_password_entry.focus())
    confirm_password_entry.bind('<Return>', lambda e: security_question_menu.focus())
    security_answer_entry.bind('<Return>', lambda e: register_btn.invoke())
    
    root.mainloop()

def log_event(event_type, username, success):
    timestamp = datetime.now()
    log_entry = f"{timestamp} - {event_type} - {username} - {'Success' if success else 'Failed'}"
    with open('security.log', 'a') as f:
        f.write(log_entry + '\n')

if __name__ == "__main__":
    main()