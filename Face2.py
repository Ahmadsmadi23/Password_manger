import tkinter as tk
from tkinter import ttk, messagebox, StringVar, Toplevel, OptionMenu
import random
import string
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import os
import shutil
import sys
from datetime import datetime, timedelta
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets

def show_login_window():
    """Show login window and return username if login successful"""
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("400x300")
    login_window.configure(bg="#FFFFFF")
    
    # Center the window
    login_window.eval('tk::PlaceWindow . center')
    
    # Main container
    main_frame = tk.Frame(login_window, bg="#FFFFFF")
    main_frame.pack(expand=True, fill='both', padx=40, pady=20)
    
    # Title
    title_label = tk.Label(main_frame, 
                          text="Password Manager Login",
                          font=("Arial", 20, "bold"),
                          bg="#FFFFFF",
                          fg="#116FA1")
    title_label.pack(pady=(0, 30))
    
    # Username
    username_frame = tk.Frame(main_frame, bg="#FFFFFF")
    username_frame.pack(fill='x', pady=10)
    
    username_label = tk.Label(username_frame,
                             text="Username:",
                             font=("Arial", 12),
                             bg="#FFFFFF")
    username_label.pack(side='left')
    
    username_var = StringVar()
    username_entry = tk.Entry(username_frame,
                            textvariable=username_var,
                            font=("Arial", 12))
    username_entry.pack(side='right', expand=True, fill='x', padx=(10, 0))
    
    # Password
    password_frame = tk.Frame(main_frame, bg="#FFFFFF")
    password_frame.pack(fill='x', pady=10)
    
    password_label = tk.Label(password_frame,
                             text="Password:",
                             font=("Arial", 12),
                             bg="#FFFFFF")
    password_label.pack(side='left')
    
    password_var = StringVar()
    password_entry = tk.Entry(password_frame,
                            textvariable=password_var,
                            font=("Arial", 12),
                            show="*")
    password_entry.pack(side='right', expand=True, fill='x', padx=(10, 0))
    
    def verify_login():
        username = username_var.get()
        password = password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        try:
            db = sqlite3.connect("user.db")
            cursor = db.cursor()
            
            # Check if user exists
            cursor.execute("""
                SELECT username FROM user_settings
                WHERE username = ?
            """, (username,))
            
            if cursor.fetchone():
                # Here you would normally verify the password
                # For now, we'll just accept any password
                login_window.quit()
                login_window.destroy()
                return username
            else:
                messagebox.showerror("Error", "Invalid username or password")
                return None
                
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {str(e)}")
            return None
        finally:
            if 'db' in locals():
                db.close()
    
    # Login button
    login_btn = tk.Button(main_frame,
                         text="Login",
                         font=("Arial", 12, "bold"),
                         command=lambda: verify_login() or None,
                         bg="#116FA1",
                         fg="white",
                         width=20)
    login_btn.pack(pady=20)
    
    # Start the login window
    login_window.mainloop()
    
    # Return the username if login was successful
    return username_var.get() if username_var.get() else None

# Get username from command line arguments or login window
if len(sys.argv) > 1:
    current_user = sys.argv[1]
else:
    current_user = show_login_window()
    if not current_user:
        sys.exit(1)  # Exit if login failed

# Basic config for security
SALT_LENGTH = 32
IV_LENGTH = 16
KEY_LENGTH = 32
HASH_ITERATIONS = 100000
DATABASE_NAME = "user.db"  # Using existing database name

# Backup settings
BACKUP_FOLDER = "backups"
MAX_BACKUP_COUNT = 5

# Database initialization
try:
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    
    # Create user_pin table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_pin (
            id INTEGER PRIMARY KEY,
            pin_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
except sqlite3.Error as e:
    messagebox.showerror("Database Error", f"Failed to initialize database: {str(e)}")
    sys.exit(1)

def make_random_salt():
    """Creates a random salt for password hashing"""
    return os.urandom(SALT_LENGTH)

def make_key_from_password(password, salt):
    """Creates an encryption key from password and salt"""
    key_maker = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=HASH_ITERATIONS,
    )
    return key_maker.derive(password.encode())

def create_key_pair():
    """Makes a new pair of encryption keys"""
    secret_key = ec.generate_private_key(ec.SECP384R1())
    public_key = secret_key.public_key()
    return secret_key, public_key

def encrypt_key(key, public_key):
    """Encrypts the key using hybrid encryption"""
    try:
        # Generate ephemeral keys
        ephemeral_private = ec.generate_private_key(ec.SECP384R1())
        ephemeral_public = ephemeral_private.public_key()
        
        # Create shared secret
        shared_secret = ephemeral_private.exchange(
            ec.ECDH(),
            public_key
        )
        
        # Derive encryption key
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pm_v1",
        ).derive(shared_secret)
        
        # Setup encryption
        random_iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES256(encryption_key), modes.CBC(random_iv)).encryptor()
        
        # Ensure key is bytes
        if isinstance(key, str):
            key = key.encode()
        
        # Add padding
        padder = padding.PKCS7(128).padder()
        padded_key = padder.update(key) + padder.finalize()
        
        # Encrypt
        encrypted_key = encryptor.update(padded_key) + encryptor.finalize()
        
        # Convert public key to bytes
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Combine everything
        return random_iv + len(ephemeral_public_bytes).to_bytes(4, 'big') + ephemeral_public_bytes + encrypted_key
    except Exception as e:
        print(f"Key encryption failed: {str(e)}")
        return None

def decrypt_key(encrypted_data, private_key):
    """Decrypts the key using hybrid decryption"""
    try:
        if encrypted_data is None:
            raise ValueError("No encrypted data provided")
            
        # Split the data
        random_iv = encrypted_data[:16]
        key_size = int.from_bytes(encrypted_data[16:20], 'big')
        ephemeral_public_data = encrypted_data[20:20+key_size]
        encrypted_key = encrypted_data[20+key_size:]
        
        # Get ephemeral public key
        ephemeral_public = serialization.load_pem_public_key(ephemeral_public_data)
        
        # Recreate shared secret
        shared_secret = private_key.exchange(
            ec.ECDH(),
            ephemeral_public
        )
        
        # Derive decryption key
        decryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pm_v1",
        ).derive(shared_secret)
        
        # Setup decryption
        decryptor = Cipher(algorithms.AES256(decryption_key), modes.CBC(random_iv)).decryptor()
        
        # Decrypt and unpad
        padded_key = decryptor.update(encrypted_key) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_key = unpadder.update(padded_key) + unpadder.finalize()
        
        return decrypted_key
        
    except Exception as e:
        print(f"Key decryption failed: {str(e)}")
        return None

def encrypt_password(password, key):
    """Encrypts a password using AES-256"""
    try:
        if not isinstance(key, bytes):
            raise ValueError("key must be bytes")
            
        random_iv = os.urandom(IV_LENGTH)
        encryptor = Cipher(algorithms.AES256(key), modes.CBC(random_iv)).encryptor()
        
        # Ensure password is bytes
        if isinstance(password, str):
            password = password.encode()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(password) + padder.finalize()
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return base64.b64encode(random_iv + encrypted).decode('utf-8')
    except Exception as e:
        print(f"Password encryption failed: {str(e)}")
        return None

def decrypt_password(encrypted_password, key):
    """Decrypts a password using AES-256"""
    try:
        if not isinstance(key, bytes):
            raise ValueError("key must be bytes")
            
        if encrypted_password is None:
            raise ValueError("No encrypted password provided")
            
        encrypted_data = base64.b64decode(encrypted_password.encode('utf-8'))
        
        random_iv = encrypted_data[:IV_LENGTH]
        encrypted = encrypted_data[IV_LENGTH:]
        
        decryptor = Cipher(algorithms.AES256(key), modes.CBC(random_iv)).decryptor()
        
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        password = unpadder.update(padded_data) + unpadder.finalize()
        
        return password.decode('utf-8')
    except Exception as e:
        print(f"Password decryption failed: {str(e)}")
        return None

def protect_password(password, key):
    """Encrypts a password securely"""
    try:
        if not isinstance(key, bytes):
            raise ValueError("key must be bytes")
            
        random_iv = os.urandom(IV_LENGTH)
        encryptor = Cipher(algorithms.AES256(key), modes.CBC(random_iv)).encryptor()
        
        # Ensure password is bytes
        if isinstance(password, str):
            password = password.encode()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(password) + padder.finalize()
        
        protected = encryptor.update(padded_data) + encryptor.finalize()
        
        return base64.b64encode(random_iv + protected).decode('utf-8')
    except Exception as e:
        print(f"Password protection failed: {str(e)}")
        return None

def reveal_password(protected_password, key):
    """Recovers the original password"""
    try:
        if not isinstance(key, bytes):
            raise ValueError("key must be bytes")
            
        if protected_password is None:
            raise ValueError("No protected password provided")
            
        encrypted_data = base64.b64decode(protected_password.encode('utf-8'))
        
        random_iv = encrypted_data[:IV_LENGTH]
        protected = encrypted_data[IV_LENGTH:]
        
        decryptor = Cipher(algorithms.AES256(key), modes.CBC(random_iv)).decryptor()
        
        padded_data = decryptor.update(protected) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        password = unpadder.update(padded_data) + unpadder.finalize()
        
        return password.decode('utf-8')
    except Exception as e:
        print(f"Password reveal failed: {str(e)}")
        return None

def setup_database():
    """Sets up the database and tables"""
    try:
        db = sqlite3.connect("user.db")
        cursor = db.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS key_storage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                wrapped_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                secret_key BLOB NOT NULL
            )
        ''')

        db.commit()
        return db, cursor

    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Setup failed: {str(e)}")
        return None, None

def clear_frame(frame):
    """Remove all widgets from a frame"""
    for widget in frame.winfo_children():
        widget.destroy()

class HoverButton(tk.Button):
    def __init__(self, master, **kw):
        tk.Button.__init__(self, master=master, **kw)
        self.defaultBackground = self["background"]
        self.defaultForeground = self["foreground"]
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.configure(relief="flat")  # جعل الزر مسطح بشكل افتراضي
    def on_enter(self, e):
        if self["background"] == "#116FA1":
            self["background"] = "#1E8BC3"  # أزرق فاتح
        elif self["background"] == "#FF4444":
            self["background"] = "#FF6666"  # أحمر فاتح
        elif self["background"] == "#f9f9f9":
            self["background"] = "#e0e0e0"  # رمادي فاتح
        
        self["cursor"] = "hand2"
        self["relief"] = "raised"
        
        # تكبير الخط
        current_font = self["font"].split()
        if len(current_font) >= 2:
            size = int(current_font[1])
            self.configure(font=(current_font[0], size + 1))

    def on_leave(self, e):
        self["background"] = self.defaultBackground
        self["foreground"] = self.defaultForeground
        self["cursor"] = ""
        self["relief"] = "flat"
        
        # إعادة حجم الخط الأصلي وإزالة تأثير الارتفاع
        current_font = self["font"].split()
        if len(current_font) >= 2:  # إذا كان الخط يحتوي على حجم
            size = int(current_font[1])
            new_font = (current_font[0], size - 1)
            self.configure(font=new_font)
    def check_password(password):
        """Check password strength and return appropriate message and color"""
        if len(password) < 8:
            return translations[current_language]["password_strength"]["Weak"], "red"
        elif len(password) < 12:
            return translations[current_language]["password_strength"]["Medium"], "orange"
        else:
            return translations[current_language]["password_strength"]["Strong"], "green"

# قاموس الأسئلة الشائعة
faq_questions = {
    "FAQs": {
        "How can I recover the master password?": "If you forget your master password, you cannot recover it due to security reasons; So you have to create a new password by clicking on the Forgot Password option located below the Enter Password option on the main page.",
        "How do I add or delete passwords?": "You can manage passwords from the main menu by selecting 'Add' or 'Delete'.",
        "What encryption is used to protect data?": "AES-256 and ECC encryption and Hash algorithm are used to securely store your passwords."
    },
    "الأسئلة الشائعة": {
        "كيف يمكنني استعادة كلمة المرور الرئيسية؟": "إذا نسيت كلمة المرور الرئيسية، لا يمكنك استعادتها لأسباب أمنية؛ لذا عليك إنشاء كلمة مرور جديدة بالنقر على خيار 'نسيت كلمة المرور' الموجود أسفل خيار 'إدخال كلمة المرور' في الصفحة الرئيسية.",
        "كيف يمكنني إضافة أو حذف كلمات المرور؟": "يمكنك إدارة كلمات المرور من القائمة الرئيسية عن طريق اختيار 'إضافة' أو 'حذف'.",
        "ما هو نوع التشفير المستخدم لحماية البيانات؟": "يتم استخدام تشفير AES-256 و ECC وخوارزمية التجزئة لتخزين كلمات المرور الخاصة بك بشكل آمن."
    }
}

# أضف هذه الدالة في بداية الملف بعد الاستيرادات مباشرة
def init_database():
    try:
        if not os.path.exists(DATABASE_NAME):
            messagebox.showerror("Error", "Database file not found. Please make sure user.db exists in the same directory.")
            return None, None
        db = sqlite3.connect(DATABASE_NAME)
        cursor = db.cursor()
        return db, cursor
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Failed to connect to database: {str(e)}")
        return None, None

def check_database_connection():
    try:
        db = sqlite3.connect(DATABASE_NAME)
        db.close()
        return True
    except:
        return False

def check_tables():
    db = sqlite3.connect("user.db")
    cursor = db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    db.close()
    return tables
    
def init_pin_database():
    """Initialize the PIN database"""
    try:
        db = sqlite3.connect("user.db")
        cursor = db.cursor()
        
        # Create user_pins table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_pins
            (username TEXT PRIMARY KEY,
                pin_hash TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                last_attempt_time TIMESTAMP)''')
        
        db.commit()
        return db, cursor
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Could not initialize PIN database: {str(e)}")
        #messagebox.showerror(translations[current_language]["warning"], 
                         #  f"{translations[current_language]['db_error']}: {str(e)}")
        return None, None

def hash_pin(pin):
    """Hash the PIN using SHA-256"""
    return hashlib.sha256(pin.encode()).hexdigest()

def verify_pin(stored_hash, input_pin):
    """Verify if input PIN matches stored hash"""
    input_hash = hash_pin(input_pin)
    return stored_hash == input_hash

def is_valid_pin(pin):
    """Check if PIN meets security requirements"""
    if not pin.isdigit() or len(pin) != 6:
        return False
        
    # Check for sequential numbers
    for i in range(len(pin)-2):
        if int(pin[i+1]) == int(pin[i]) + 1 and int(pin[i+2]) == int(pin[i]) + 2:
            return False
            
    # Check for repeated numbers
    if any(pin.count(d) > 2 for d in pin):
        return False
        
    return True

def check_pin_attempts(username):
    """Check if user can attempt PIN entry"""
    db, cursor = init_pin_database()
    if not db:
        return False
        
    try:
        cursor.execute("""
            SELECT failed_attempts, last_attempt_time
            FROM user_pins
            WHERE username = ?
        """, (username,))
        result = cursor.fetchone()
        
        if not result:
            return True
            
        failed_attempts, last_attempt = result
        
        if failed_attempts >= 3:
            if last_attempt:
                last_attempt = datetime.fromisoformat(last_attempt)
                if datetime.now() - last_attempt < timedelta(minutes=5):
                    return False
                    
            # Reset attempts after timeout
            cursor.execute("""
                UPDATE user_pins
                SET failed_attempts = 0,
                    last_attempt_time = NULL
                WHERE username = ?
            """, (username,))
            db.commit()
            
        return True
        
    finally:
        db.close()

def update_pin_attempts(username, success):
    """Update PIN attempt counter"""
    db, cursor = init_pin_database()
    if not db:
        return
        
    try:
        if success:
            # Reset attempts on successful verification
            cursor.execute("""
                UPDATE user_pins
                SET failed_attempts = 0,
                    last_attempt_time = NULL
                WHERE username = ?
            """, (username,))
        else:
            # Increment failed attempts
            cursor.execute("""
                UPDATE user_pins
                SET failed_attempts = failed_attempts + 1,
                    last_attempt_time = ?
                WHERE username = ?
            """, (datetime.now().isoformat(), username))
            
        db.commit()
    finally:
        db.close()

# dictionary to save the passwords for the apps 
default_passwords = {}

# Translation dictionaries
translations = {
    "en": {
        "title": " Password Manager",
        "welcome": "Welcome! Manage your passwords securely.",
        "home": "🏠 Home",
        "support": "🛠 Support",
        "settings": "Settings",
        "backup": "Backup",
        "search": "Search App:",
        "categories": [
            "Marketing & Social Media",
            "Financial & Banking Services",
            "Customer Support",
            "Human Resources",
            "Project Management",
            "Data & Analytics",
            "Communication Tools",
            "File Storage & Collaboration",
            "Cybersecurity & Access Control",
            "Sales & CRM",
            "Productivity & Office Tools",
            "Other"
        ],
        "add_app": "Add New Application",
        "password_strength": {"Weak": "Weak", "Medium": "Medium", "Strong": "Strong"},
        "change_pass": "Change",
        "change": "Change",
        "delete": "Delete",
        "show_pass": "🔒",
        "hide_pass": "👁",
        "app_name": "App Name",
        "select_category": "Select Category",
        "enter_password": "Enter Password",
        "generate": "Generate",
        "save": "Save",
        "support_title": "How can we help you?",
        "support_options": ["Report a Bug", "Request a Feature", "FAQs"],
        "write_issue": "Write your issue:",
        "submit": "Submit",
        "settings_title": "Settings",
        "select_language": "Select Language",
        "select_mode": "Select Mode",
        "apply": "Apply",
        "languages": ["English", "العربية"],
        "modes": ["Light Mode", "Dark Mode"],
        "logout": "Logout",
        "logout_confirm": "Are you sure you want to logout?",
        "yes": "Yes",
        "no": "No",
        "goodbye": "Goodbye! See you soon.",
        "warning": "Warning",
        "success": "Success",
        "password_length": "Password must be at least 8 characters long!",
        "password_changed": "Password has been changed successfully!",
        "no_apps": "No applications found in this category",
        "missing_app_name": "Please provide the app name!",
        "app_exists": "Application already exists!",
        "db_error": "Could not connect to database",
        "add_success": "Password has been added successfully!",
        "change_password_for": "Change Password for",
        "feedback_thanks": "Thank you for your feedback!",
        "language": "Language",
        "theme": "Theme",
        "light": "Light",
        "dark": "Dark",
        "add_new_app": "Add New Application",
        "category": "Category",
        "password": "Password",
        "generate": "Generate Password",
        "save_app": "Save Application",
        "social_media": "Social Media",
        "email": "Email",
        "banking": "Banking",
        "shopping": "Shopping",
        "other": "Other",
        "no_apps_found": "No applications found",
        "delete_confirm": "Are you sure you want to delete this application?",
        "delete_success": "Application deleted successfully",
        "copy_success": "Password copied to clipboard",
        "search": "Search applications...",
        "faqs": "Frequently Asked Questions",
        "show": "Show",
        "confirm": "Confirm",
        "backup_management": "Backup Management",
        "create_new_backup": "Create New Backup",
        "available_backups": "Available Backups",
        "restore_selected": "Restore Selected Backup",
        "backup_created": "Backup created successfully",
        "backup_error": "Error creating backup",
        "restore_confirm": "Are you sure you want to restore this backup?",
        "select_backup": "Please select a backup to restore",
        "restore_success": "Backup restored successfully",
        "restore_error": "Error restoring backup",
        "backup_file_not_found": "Backup file not found",
        "pin_setup": "Setup PIN Code",
        "pin_enter": "Enter PIN Code",
        "pin_confirm": "Confirm PIN Code",
        "pin_rules": "PIN must be 6 digits and not contain sequential or repeated numbers",
        "pin_mismatch": "PIN codes do not match",
        "pin_invalid": "Invalid PIN format",
        "pin_success": "PIN setup successful",
        "pin_error": "Error setting up PIN",
        "pin_verify": "Please enter your PIN",
        "pin_incorrect": "Incorrect PIN",
        "pin_attempts": "Too many incorrect attempts. Please wait 5 minutes",
        "pin_forgot": "Forgot PIN?",
        "pin_reset": "Reset PIN",
        "pin_current": "Current PIN",
        "pin_new": "New PIN",
        "pin_changed": "PIN changed successfully",
        "two_factor_auth": "Two-Factor Authentication",
        "two_factor_settings": "Two-Factor Authentication Settings",
        "enable_2fa": "Enable Two-Factor Authentication",
        "disable_2fa": "Disable Two-Factor Authentication",
        "confirm_disable_2fa": "Are you sure you want to disable Two-Factor Authentication?",
        "2fa_disabled": "Two-Factor Authentication has been disabled",
        "2fa_enabled": "Two-Factor Authentication has been enabled"
    },
    "ar": {
        "title": "🔒 مدير كلمات المرور",
        "welcome": "مرحباً! قم بإدارة كلمات المرور الخاصة بك بأمان.",
        "home": "🏠 الرئيسية",
        "support": "🛠 الدعم",
        "settings": "الإعدادات",
        "backup": "النسخ الاحتياطي",
        "search": "ابحث عن التطبيق:",
        "categories": [
            "التسويق ووسائل التواصل",
            "الخدمات المالية والمصرفية",
            "دعم العملاء",
            "الموارد البشرية",
            "إدارة المشاريع",
            "البيانات والتحليلات",
            "أدوات الاتصال",
            "تخزين الملفات والتعاون",
            "الأمن السيبراني والتحكم في الوصول",
            "المبيعات وإدارة علاقات العملاء",
            "أدوات الإنتاجية والمكتب",
            "أخرى"
        ],
        "add_app": "إضافة تطبيق جديد",
        "password_strength": {"Weak": "ضعيف", "Medium": "متوسط", "Strong": "قوي"},
        "change_pass": "تغيير",
        "change": "تغيير",
        "delete": "حذف",
        "show_pass": "🔒",
        "hide_pass": "👁",
        "app_name": "اسم التطبيق",
        "select_category": "اختر الفئة",
        "enter_password": "أدخل كلمة المرور",
        "generate": "توليد كلمة مرور",
        "save": "حفظ",
        "support_title": "كيف يمكننا مساعدتك؟",
        "support_options": ["الإبلاغ عن خطأ", "طلب ميزة جديدة", "الأسئلة الشائعة"],
        "write_issue": "اكتب مشكلتك",
        "submit": "إرسال",
        "settings_title": "الإعدادات",
        "select_language": "اختر اللغة",
        "select_mode": "اختر الوضع",
        "apply": "تطبيق",
        "languages": ["English", "العربية"],
        "modes": ["الوضع الفاتح", "الوضع المظلم"],
        "logout": "تسجيل الخروج",
        "logout_confirm": "هل أنت متأكد من تسجيل الخروج؟",
        "yes": "نعم",
        "no": "لا",
        "goodbye": "مع السلامة! نراك قريباً",
        "warning": "تحذير",
        "success": "تم بنجاح",
        "password_length": "يجب أن تكون كلمة المرور 8 أحرف على الأقل!",
        "password_changed": "تم تغيير كلمة المرور بنجاح!",
        "no_apps": "لا توجد تطبيقات في هذه الفئة",
        "missing_app_name": "الرجاء إدخال اسم التطبيق!",
        "app_exists": "التطبيق موجود مسبقاً!",
        "db_error": "لا يمكن الاتصال بقاعدة البيانات",
        "add_success": "تم إضافة كلمة المرور بنجاح!",
        "change_password_for": "تغيير كلمة المرور لـ",
        "feedback_thanks": "شكراً على ملاحظاتك!",
        "language": "اللغة",
        "theme": "المظهر",
        "light": "فاتح",
        "dark": "داكن",
        "add_new_app": "إضافة تطبيق جديد",
        "category": "الفئة",
        "password": "كلمة المرور",
        "generate": "توليد كلمة مرور",
        "save_app": "حفظ التطبيق",
        "social_media": "وسائل التواصل الاجتماعي",
        "email": "البريد الإلكتروني",
        "banking": "الخدمات المصرفية",
        "shopping": "التسوق",
        "other": "أخرى",
        "no_apps_found": "لم يتم العثور على تطبيقات",
        "delete_confirm": "هل أنت متأكد من حذف هذا التطبيق؟",
        "delete_success": "تم حذف التطبيق بنجاح",
        "copy_success": "تم نسخ كلمة المرور إلى الحافظة",
        "search": "البحث عن التطبيقات...",
        "faqs": "الأسئلة الشائعة",
        "show": "عرض",
        "confirm": "تأكيد",
        "backup_management": "إدارة النسخ الاحتياطية",
        "create_new_backup": "إنشاء نسخة احتياطية جديدة",
        "available_backups": "النسخ الاحتياطية المتوفرة",
        "restore_selected": "استعادة النسخة المحددة",
        "backup_created": "تم إنشاء النسخة الاحتياطية بنجاح",
        "backup_error": "خطأ في إنشاء النسخة الاحتياطية",
        "restore_confirm": "هل أنت متأكد من استعادة هذه النسخة الاحتياطية؟",
        "select_backup": "الرجاء اختيار نسخة احتياطية للاستعادة",
        "restore_success": "تمت استعادة النسخة الاحتياطية بنجاح",
        "restore_error": "خطأ في استعادة النسخة الاحتياطية",
        "backup_file_not_found": "لم يتم العثور على ملف النسخة الاحتياطية",
        "pin_setup": "إعداد رمز PIN",
        "pin_enter": "أدخل رمز PIN",
        "pin_confirm": "تأكيد رمز PIN",
        "pin_rules": "يجب أن يتكون PIN من 6 أرقام ولا يحتوي على أرقام متسلسلة أو متكررة",
        "pin_mismatch": "رموز PIN غير متطابقة",
        "pin_invalid": "صيغة PIN غير صالحة",
        "pin_success": "تم إعداد PIN بنجاح",
        "pin_error": "خطأ في إعداد PIN",
        "pin_verify": "الرجاء إدخال رمز PIN",
        "pin_incorrect": "رمز PIN غير صحيح",
        "pin_attempts": "محاولات خاطئة كثيرة. يرجى الانتظار 5 دقائق",
        "pin_forgot": "نسيت رمز PIN؟",
        "pin_reset": "تغيير رمز PIN",
        "pin_current": "رمز PIN الحالي",
        "pin_new": "رمز PIN الجديد",
        "pin_changed": "تم تغيير PIN بنجاح",
        "two_factor_auth": "المصادقة الثنائية",
        "two_factor_settings": "إعدادات المصادقة الثنائية",
        "enable_2fa": "تفعيل المصادقة الثنائية",
        "disable_2fa": "تعطيل المصادقة الثنائية",
        "confirm_disable_2fa": "هل أنت متأكد من تعطيل المصادقة الثنائية؟",
        "2fa_disabled": "تم تعطيل المصادقة الثنائية",
        "2fa_enabled": "تم تفعيل المصادقة الثنائية"
    }
}

# Global variables
current_language = "en"  # Default language
current_theme = "light"  # Default theme

def check_and_update_database_structure():
    """Check and update database structure if needed"""
    try:
        db = sqlite3.connect(DATABASE_NAME)
        cursor = db.cursor()
        
        # Get list of existing tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [table[0] for table in cursor.fetchall()]
        
        # Check and create missing tables
        if 'apps' not in existing_tables:
            cursor.execute('''CREATE TABLE IF NOT EXISTS apps
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                app_name TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                category TEXT NOT NULL,
                UNIQUE(username, app_name))''')
                
        if 'user_settings' not in existing_tables:
            cursor.execute('''CREATE TABLE IF NOT EXISTS user_settings
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                language TEXT DEFAULT 'en',
                theme TEXT DEFAULT 'light')''')
                
        if 'encryption_keys' not in existing_tables:
            cursor.execute('''CREATE TABLE IF NOT EXISTS encryption_keys
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                master_key BLOB NOT NULL)''')
                
        if 'user_pins' not in existing_tables:
            cursor.execute('''CREATE TABLE IF NOT EXISTS user_pins
                (username TEXT PRIMARY KEY,
                pin_hash TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                last_attempt_time TIMESTAMP)''')
        
        # Check for default user settings
        cursor.execute("SELECT COUNT(*) FROM user_settings WHERE username = ?", (current_user,))
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO user_settings (username, language, theme)
                VALUES (?, ?, ?)
            """, (current_user, current_language, current_theme))
            
        # Check for encryption keys
        cursor.execute("SELECT COUNT(*) FROM encryption_keys WHERE username = ?", (current_user,))
        if cursor.fetchone()[0] == 0:
            salt = os.urandom(SALT_LENGTH)
            master_key = os.urandom(KEY_LENGTH)
            cursor.execute("""
                INSERT INTO encryption_keys (username, salt, master_key)
                VALUES (?, ?, ?)
            """, (current_user, salt, master_key))
        
        db.commit()
        return True
        
    except Exception as e:
        print(f"Error checking/updating database: {str(e)}")
        return False
    finally:
        if 'db' in locals():
            db.close()

def initialize_application():
    """Initialize the application and ensure database compatibility"""
    try:
        # First check if database exists
        if not os.path.exists(DATABASE_NAME):
            messagebox.showerror("Error", "Database file not found. Please make sure user.db exists in the same directory.")
            return False
            
        # Then check and update database structure
        if not check_and_update_database_structure():
            messagebox.showerror("Error", "Failed to update database structure.")
            return False
            
        return True
        
    except Exception as e:
        print(f"Error initializing application: {str(e)}")
        return False

def get_master_key():
    """Retrieve the master key for the current user"""
    try:
        db = sqlite3.connect("user.db")
        cursor = db.cursor()

        # First check if the table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='encryption_keys'
        """)
        if not cursor.fetchone():
            raise Exception("Encryption keys table does not exist")
        
        # Then check if the column exists
        cursor.execute("PRAGMA table_info(encryption_keys)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'master_key' not in columns:
            raise Exception("master_key column does not exist")
        
        cursor.execute("""
            SELECT master_key FROM encryption_keys
            WHERE username = ?
        """, (current_user,))
        
        result = cursor.fetchone()
        if result:
            return result[0]  # Return the master key as bytes
        return None
        
    except Exception as e:
        print(f"Error retrieving master key: {str(e)}")
        return None
    finally:
        if 'db' in locals():
            db.close()

def encrypt_password(password, master_key):
    """Encrypts a password using AES-256"""
    try:
        if not isinstance(master_key, bytes):
            raise ValueError("master_key must be bytes")
            
        if not password:
            raise ValueError("password cannot be empty")
            
        # Generate a random IV
        iv = os.urandom(IV_LENGTH)
        
        # Create cipher
        cipher = Cipher(algorithms.AES256(master_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Convert password to bytes and pad
        password_bytes = password.encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(password_bytes) + padder.finalize()
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext and encode
        encrypted = base64.b64encode(iv + ciphertext)
        return encrypted.decode('utf-8')
        
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None

def decrypt_password(encrypted_password, master_key):
    """Decrypts a password using AES-256"""
    try:
        if not isinstance(master_key, bytes):
            raise ValueError("master_key must be bytes")
            
        if not encrypted_password:
            raise ValueError("encrypted_password cannot be empty")
            
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_password.encode('utf-8'))
        
        # Extract IV and ciphertext
        iv = encrypted_data[:IV_LENGTH]
        ciphertext = encrypted_data[IV_LENGTH:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES256(master_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Decrypt and unpad
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        password_bytes = unpadder.update(padded_data) + unpadder.finalize()
        
        # Convert back to string
        return password_bytes.decode('utf-8')
        
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

def add_new_bottun(new_pass_window, category_var, app_name_var, password_entry):
    new_password = password_entry.get()
    app_name = app_name_var.get()
    category = category_var.get()
    
    # Convert category to English if needed
    if current_language == "ar":
        categories_ar = translations["ar"]["categories"]
        categories_en = translations["en"]["categories"]
        if category in categories_ar:
            index = categories_ar.index(category)
            category = categories_en[index]
    
    if not app_name:
        messagebox.showwarning(translations[current_language]["warning"], 
                             translations[current_language]["missing_app_name"])
        return
    
    if len(new_password) < 8:
        messagebox.showwarning(translations[current_language]["warning"], 
                             translations[current_language]["password_length"])
        return
    
    try:
        db = sqlite3.connect("user.db")
        cursor = db.cursor()
        
        # Check if app exists
        cursor.execute("""
            SELECT app_name FROM apps 
            WHERE username = ? AND app_name = ?
        """, (current_user, app_name))
        
        if cursor.fetchone():
            messagebox.showerror(translations[current_language]["warning"], 
                               translations[current_language]["app_exists"])
            return
            
        # Get master key
        master_key = get_master_key()
        if not master_key:
            raise Exception("Failed to retrieve master key")
            
        # Encrypt the password
        encrypted_password = encrypt_password(new_password, master_key)
        if not encrypted_password:
            raise Exception("Failed to encrypt password")
            
        # Store the encrypted password
        cursor.execute("""
            INSERT INTO apps (username, app_name, encrypted_password, category)
            VALUES (?, ?, ?, ?)
        """, (current_user, app_name, encrypted_password, category))
        
        db.commit()
        
        messagebox.showinfo(translations[current_language]["success"], 
                          translations[current_language]["add_success"])
        show_category_apps(category, frame, "")
        new_pass_window.destroy()
        
    except Exception as e:
        messagebox.showerror(translations[current_language]["warning"], 
                           f"{translations[current_language]['db_error']}: {str(e)}")
    finally:
        if 'db' in locals():
            db.close()

def show_category_apps(category, frame, search_text=""):
    clear_frame(frame)
    
    # Convert category to English if needed
    if current_language == "ar":
        categories_ar = translations["ar"]["categories"]
        categories_en = translations["en"]["categories"]
        if category in categories_ar:
            index = categories_ar.index(category)
            category = categories_en[index]

    try:
        db = sqlite3.connect("user.db")
        cursor = db.cursor()
        
        # Get master key
        master_key = get_master_key()
        if not master_key:
            raise Exception("Failed to retrieve master key")

        if search_text:
            cursor.execute("""
                SELECT app_name, encrypted_password, category FROM apps 
                WHERE username = ? AND category = ? AND app_name LIKE ?
            """, (current_user, category, f"%{search_text}%"))
        else:
            cursor.execute("""
                SELECT app_name, encrypted_password, category FROM apps 
                WHERE username = ? AND category = ?
            """, (current_user, category))
        
        apps = cursor.fetchall()
        
        if not apps:
            no_apps_label = tk.Label(frame, text=translations[current_language]["no_apps"], 
                                   font=("Arial", 12), bg="white")
            no_apps_label.pack(pady=20)
            return

        for app in apps:
            app_frame = tk.Frame(frame, bg="white")
            app_frame.pack(fill="x", padx=10, pady=5)
            
            app_name = app[0]
            encrypted_password = app[1]
            
            # Decrypt the password
            try:
                decrypted_password = decrypt_password(encrypted_password, master_key)
                if decrypted_password is None:
                    decrypted_password = "Error decrypting password"
            except Exception as e:
                decrypted_password = "Error decrypting password"
                print(f"Error decrypting password for {app_name}: {str(e)}")
            
            name_label = tk.Label(app_frame, text=app_name, font=("Arial", 12), bg="white")
            name_label.pack(side="left", padx=5)
            
            # Create password entry
            password_entry = tk.Entry(app_frame, font=("Arial", 12), show="*", width=20)
            password_entry.insert(0, decrypted_password)
            password_entry.config(state='readonly')
            password_entry.pack(side="left", padx=5)
            
            # Create show/hide password button with eye icon
            show_password = StringVar(value="👁️")
            show_btn = tk.Button(app_frame, 
                               textvariable=show_password,
                               font=("Arial", 12),
                               command=lambda p=password_entry, s=show_password: switch_password(p, s),
                               bg="white",
                               relief="flat")
            show_btn.pack(side="left", padx=2)
            apply_hover_effect(show_btn)
            
            strength_text, strength_color = check_password(decrypted_password)
            strength_label = tk.Label(app_frame, text=strength_text, font=("Arial", 10), 
                                    fg=strength_color, bg="white")
            strength_label.pack(side="left", padx=5)
            
            change_btn = tk.Button(app_frame, text=translations[current_language]["change"], 
                                 command=lambda n=app_name, s=strength_label: change_bottun(n, s))
            change_btn.pack(side="right", padx=2)
            apply_hover_effect(change_btn)
            
            delete_btn = tk.Button(app_frame, text=translations[current_language]["delete"], 
                                 command=lambda n=app_name: delete_app(n, category))
            delete_btn.pack(side="right", padx=2)
            apply_hover_effect(delete_btn)
            
    except Exception as e:
        messagebox.showerror(translations[current_language]["warning"], 
                           f"{translations[current_language]['db_error']}: {str(e)}")
    finally:
        if 'db' in locals():
            db.close()

def delete_app(app_name, category):
    """Delete an app and its password"""
    if messagebox.askyesno(translations[current_language]["confirm"], 
                          translations[current_language]["delete_confirm"]):
        try:
            db = sqlite3.connect("user.db")
            cursor = db.cursor()
            
            cursor.execute("""
                DELETE FROM apps 
                WHERE username = ? AND app_name = ?
            """, (current_user, app_name))
            
            db.commit()
            
            if cursor.rowcount > 0:
                messagebox.showinfo(translations[current_language]["success"], 
                                  translations[current_language]["delete_success"])
                show_category_apps(category, frame, search_entry.get())
            else:
                messagebox.showerror(translations[current_language]["warning"], 
                                   "Failed to delete app")
                
        except Exception as e:
            messagebox.showerror(translations[current_language]["warning"], 
                               f"{translations[current_language]['db_error']}: {str(e)}")
        finally:
            if 'db' in locals():
                db.close()

def show_password(password):
    popup = Toplevel()
    popup.title(translations[current_language]["password"])
    popup.geometry("300x100")
    
    password_label = tk.Label(popup, text=password, font=("Arial", 12))
    password_label.pack(pady=20)
    
    copy_btn = tk.Button(popup, text=translations[current_language]["copy"], 
                        command=lambda: [copy_to_clipboard(password), popup.destroy()])
    copy_btn.pack(pady=10)
    apply_hover_effect(copy_btn)

def generate_bottun(password_entry):
    """Generate a strong random password using cryptographically secure random number generation"""
    # Define character sets
    length = 12
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:'<>,.?/"
    
    # Ensure at least one of each type using secure random selection
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]
    
    # Fill the rest randomly using secure random selection
    all_chars = lowercase + uppercase + digits + symbols
    password.extend(secrets.choice(all_chars) for _ in range(length - len(password)))
    
    # Shuffle the password using Fisher-Yates algorithm with secure random numbers
    for i in range(len(password) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password[i], password[j] = password[j], password[i]
    
    generated_password = ''.join(password)
    
    # Update the entry
    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated_password)
    password_entry.config(show="")  # Show the password temporarily
    
    # Force immediate progress bar update
    password_entry.event_generate('<<Modified>>')

def evaluate_password_strength(password):
    """Evaluate password strength and return score and color"""
    score = 0
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    
    # Character variety checks
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1
    
    # Calculate percentage (max score is 6)
    percentage = (score / 6) * 100
    
    # Determine color based on score
    if score < 3:
        color = "#FF4444"  # Red
    elif score < 5:
        color = "#FFA500"  # Yellow
    else:
        color = "#00C851"  # Green
    
    return percentage, color

def show_new_apps_window():
    new_pass_window = Toplevel()
    new_pass_window.title(translations[current_language]["add_app"])
    new_pass_window.geometry("400x500")
    new_pass_window.configure(bg="#FFFFFF")
    
    # Main container frame
    main_container = tk.Frame(new_pass_window, bg="#FFFFFF")
    main_container.pack(expand=True, fill='both', padx=40, pady=20)
    
    # Title
    title_label = tk.Label(main_container, 
                          text=translations[current_language]["add_app"],
                          font=("Arial", 16, "bold"),
                          bg="#FFFFFF",
                          fg="#116FA1")
    title_label.pack(pady=(0, 20))
    
    # Category selection
    category_frame = tk.Frame(main_container, bg="#FFFFFF")
    category_frame.pack(fill='x', pady=10)
    
    tk.Label(category_frame, 
             text=translations[current_language]["select_category"], 
             font=("Arial", 12),
             bg="#FFFFFF",
             fg="#333333").pack(pady=(0, 5))
    
    category_var = StringVar(new_pass_window)
    category_var.set(translations[current_language]["categories"][0])
    
    category_menu = StyledOptionMenu(category_frame,
                                   category_var,
                                   *translations[current_language]["categories"])
    category_menu.pack()
    
    # App name
    app_name_frame = tk.Frame(main_container, bg="#FFFFFF")
    app_name_frame.pack(fill='x', pady=20)
    
    tk.Label(app_name_frame, 
             text=translations[current_language]["app_name"], 
             font=("Arial", 12),
             bg="#FFFFFF",
             fg="#333333").pack(pady=(0, 5))
    
    app_name_var = StringVar(new_pass_window)
    name_entry = tk.Entry(app_name_frame, 
                         textvariable=app_name_var,
                         font=("Arial", 12),
                         relief="solid",
                         bd=1)
    name_entry.pack(fill='x')
    
    # Password
    password_frame = tk.Frame(main_container, bg="#FFFFFF")
    password_frame.pack(fill='x', pady=20)
    
    tk.Label(password_frame, 
             text=translations[current_language]["enter_password"], 
             font=("Arial", 12),
             bg="#FFFFFF",
             fg="#333333").pack(pady=(0, 5))
    
    password_container = tk.Frame(password_frame, bg="#FFFFFF")
    password_container.pack(fill='x')
    
    password_entry = tk.Entry(password_container,
                            font=("Arial", 12),
                            relief="solid",
                            bd=1,
                            show="*")
    password_entry.pack(side='left', expand=True, fill='x', padx=(0, 5))
    
    generate_btn = tk.Button(password_container,
                            text=translations[current_language]["generate"], 
                            font=("Arial", 10),
                            command=lambda: generate_bottun(password_entry),
                            bg="#116FA1",
                            fg="white")
    generate_btn.pack(side='right')
    apply_hover_effect(generate_btn)
    
    # Password strength progress bar
    progress_frame = tk.Frame(main_container, bg="#FFFFFF")
    progress_frame.pack(fill='x', pady=(10, 0))
    
    # Background frame for progress bar
    progress_bg = tk.Frame(progress_frame, bg="#E0E0E0", height=5)
    progress_bg.pack(fill='x')
    
    # Progress bar
    progress_bar = tk.Frame(progress_bg, bg="#FF4444", height=5)
    progress_bar.place(x=0, y=0, relwidth=0)
    
    def update_strength_indicator(*args):
        password = password_entry.get()
        if not password:
            progress_bar.place(x=0, y=0, relwidth=0)
            return
            
        percentage, color = evaluate_password_strength(password)
        progress_bar.configure(bg=color)
        progress_bar.place(x=0, y=0, relwidth=percentage/100)
        progress_bar.update_idletasks()  # Force immediate visual update
    
    # Bind multiple events to ensure immediate updates
    password_entry.bind('<KeyRelease>', update_strength_indicator)
    password_entry.bind('<<Modified>>', update_strength_indicator)
    password_entry.bind('<FocusOut>', update_strength_indicator)
    
    # Save button
    save_btn = tk.Button(main_container,
                        text=translations[current_language]["save"], 
                        font=("Arial", 12, "bold"),
                        command=lambda: add_new_bottun(new_pass_window, category_var, app_name_var, password_entry),
                        bg="#116FA1",
                        fg="white",
                        width=20,
                        height=2)
    save_btn.pack(pady=30)
    apply_hover_effect(save_btn)

def open_support_window():
    support_window = Toplevel()
    support_window.title(translations[current_language]["support"])
    support_window.geometry("600x600")
    support_window.configure(bg="#FFFFFF")

    # Main container
    main_container = tk.Frame(support_window, bg="#FFFFFF")
    main_container.pack(fill='both', expand=True, padx=20, pady=10)

    # Title
    title_label = tk.Label(main_container, 
                          text=translations[current_language]["support_title"], 
                          font=("Arial", 16, "bold"),
                          bg="#FFFFFF",
                          fg="#116FA1")
    title_label.pack(pady=10)

    # Options dropdown
    dropdown_frame = tk.Frame(main_container, bg="#FFFFFF")
    dropdown_frame.pack(fill='x', pady=10)
    
    selected_option = StringVar(support_window)
    selected_option.set(translations[current_language]["support_options"][0])
    
    option_menu = StyledOptionMenu(dropdown_frame,
                                 selected_option,
                                 *translations[current_language]["support_options"])
    option_menu.pack()

    # Content frame with scrollbar
    canvas = tk.Canvas(main_container, bg="#FFFFFF")
    scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
    content_frame = tk.Frame(canvas, bg="#FFFFFF")
    
    canvas.configure(yscrollcommand=scrollbar.set)
    
    def show_faq_buttons():
        # Clear previous content
        for widget in content_frame.winfo_children():
            widget.destroy()
            
        faq_key = "FAQs" if current_language == "en" else "الأسئلة الشائعة"
        for question, answer in faq_questions[faq_key].items():
            # Question button with blue background
            question_frame = tk.Frame(content_frame, bg="#116FA1", padx=10, pady=5)
            question_frame.pack(fill='x', pady=(10, 0))
            
            question_label = tk.Label(question_frame,
                                    text=question,
                                    font=("Arial", 11, "bold"),
                                    bg="#116FA1",
                                    fg="white",
                                    wraplength=500,
                                    justify='left')
            question_label.pack(fill='x', pady=5)
            
            # Answer with light gray background
            answer_frame = tk.Frame(content_frame, bg="#F5F5F5", padx=15, pady=10)
            answer_frame.pack(fill='x')
            
            answer_label = tk.Label(answer_frame,
                                  text=answer,
                                  font=("Arial", 10),
                                  bg="#F5F5F5",
                                  fg="#333333",
                                  wraplength=500,
                                  justify='left')
            answer_label.pack(fill='x')

    def show_issue_form():
        # Clear previous content
        for widget in content_frame.winfo_children():
            widget.destroy()
            
        issue_frame = tk.Frame(content_frame, bg="#FFFFFF")
        issue_frame.pack(fill='x', pady=20)
        
        issue_label = tk.Label(issue_frame, 
                             text=translations[current_language]["write_issue"], 
                             font=("Arial", 12, "bold"),
                             bg="#FFFFFF",
                             fg="#333333")
        issue_label.pack(pady=5)

        issue_text = tk.Text(issue_frame, height=5, width=50, font=("Arial", 11))
        issue_text.pack(pady=10)

        def submit_this_issue():
            messagebox.showinfo("Success", "Thank you for your feedback!" if current_language == "en" else "شكراً على ملاحظاتك!")
            issue_text.delete(1.0, tk.END)

        submit_btn = tk.Button(issue_frame, 
                             text=translations[current_language]["submit"], 
                             font=("Arial", 12),
                             command=lambda: submit_issue(issue_text),
                             bg="#116FA1",
                             fg="white",
                             width=20)
        submit_btn.pack(pady=10)
        apply_hover_effect(submit_btn)

    def update_content(*args):
        selected = selected_option.get()
        if selected == translations[current_language]["support_options"][2]:  # FAQ option
            show_faq_buttons()
        else:
            show_issue_form()
        
        # Update canvas scroll region
        content_frame.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

    # Set up the scrollable area
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    canvas.create_window((0, 0), window=content_frame, anchor="nw", width=canvas.winfo_reqwidth())
    
    content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas.find_all()[0], width=e.width))

    selected_option.trace('w', update_content)
    update_content()  # Call initially to set up the correct view

def logout_user():
    if messagebox.askyesno(
        translations[current_language]["logout"],
        translations[current_language]["logout_confirm"],
        icon='question'
    ):
        messagebox.showinfo("", translations[current_language]["goodbye"])
        root.destroy()  # إغلاق التطبيق
        # يمكنك هنا إضافة أي تنظيف إضافي للبيانات إذا كنت تحتاج إلى ذلك

def open_settings_window():
    settings_window = Toplevel()
    settings_window.title(translations[current_language]["settings"])
    settings_window.geometry("400x400")
    settings_window.configure(bg="#FFFFFF")
    
    # Main container frame
    main_container = tk.Frame(settings_window, bg="#FFFFFF")
    main_container.pack(expand=True, fill='both', padx=40, pady=20)
    
    # Title
    title_label = tk.Label(main_container, 
                          text=translations[current_language]["settings"],
                          font=("Arial", 20, "bold"),
                          bg="#FFFFFF",
                          fg="#116FA1")
    title_label.pack(pady=(0, 30))
    
    # Language settings
    language_frame = tk.Frame(main_container, bg="#FFFFFF")
    language_frame.pack(fill='x', pady=15)
    
    language_label = tk.Label(language_frame, 
                            text=translations[current_language]["language"],
                            font=("Arial", 12, "bold"),
                            bg="#FFFFFF",
                            fg="#333333")
    language_label.pack(side=tk.LEFT)
    
    language_var = tk.StringVar(value=current_language)
    language_menu = StyledOptionMenu(language_frame,
                                   language_var,
                                   "en", "ar")
    language_menu.pack(side=tk.RIGHT)
    
    # Theme settings
    theme_frame = tk.Frame(main_container, bg="#FFFFFF")
    theme_frame.pack(fill='x', pady=15)
    
    theme_label = tk.Label(theme_frame, 
                          text=translations[current_language]["theme"],
                          font=("Arial", 12, "bold"),
                          bg="#FFFFFF",
                          fg="#333333")
    theme_label.pack(side=tk.LEFT)
    
    theme_var = tk.StringVar(value=current_theme)
    theme_menu = StyledOptionMenu(theme_frame,
                                theme_var,
                                "light", "dark")
    theme_menu.pack(side=tk.RIGHT)
    
    # Separator
    separator = tk.Frame(main_container, height=2, bg="#EEEEEE")
    separator.pack(fill='x', pady=25)
    
    # Save button
    save_btn = tk.Button(main_container,
                        text=translations[current_language]["save"],
                        font=("Arial", 14, "bold"),
                        command=lambda: save_settings(settings_window, language_var.get(), theme_var.get()),
                        bg="#116FA1",
                        fg="white",
                        width=20,
                        height=2)
    save_btn.pack(pady=20)
    apply_hover_effect(save_btn)

def save_settings(window, new_language, new_theme):
    global current_language, current_theme
    
    try:
        # Get user ID from database
        conn = sqlite3.connect('user.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM user_settings WHERE username = ?", (current_user,))
        result = cursor.fetchone()
        if not result:
            raise Exception("User settings not found")
        user_id = result[0]
        conn.close()
        
        # Update language
        if new_language != current_language:
            current_language = new_language
            save_user_settings(user_id, "language", new_language)
            update_ui_language()
        
        # Update theme
        if new_theme != current_theme:
            current_theme = new_theme
            save_user_settings(user_id, "theme", new_theme)
            apply_theme()
        
        window.destroy()
        
    except Exception as e:
        messagebox.showerror(translations[current_language]["warning"],
                           translations[current_language]["db_error"])

def save_user_settings(user_id, setting_type, value):
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    try:
        cursor.execute(f"UPDATE user_settings SET {setting_type} = ? WHERE id = ?", (value, user_id))
        conn.commit()
    except Exception as e:
        raise e
    finally:
        conn.close()

def change_language(lang):
    global current_language
    current_language = lang
    update_ui_language()

def update_ui_language():
    # تحديث عنوان النافذة
    root.title(translations[current_language]["title"])
    
    # تحديث الترويسة
    header_label.config(text=translations[current_language]["title"])
    welcome_label.config(text=translations[current_language]["welcome"])
    
    # تحديث أزرار القائمة
    home_btn.config(text=translations[current_language]["home"])
    support_btn.config(text=translations[current_language]["support"])
    settings_btn.config(text=translations[current_language]["settings"])
    backup_btn.config(text=translations[current_language]["backup"])
    
    # تحديث البحث والفئات
    search_label.config(text=translations[current_language]["search"])
    category_label.config(text=translations[current_language]["select_category"])
    
    # تحديث القائمة المنسدلة للفئات
    category_var.set(translations[current_language]["categories"][0])
    menu = category_dropdown['menu']
    menu.delete(0, 'end')
    for category in translations[current_language]["categories"]:
        menu.add_command(label=category, 
                        command=lambda value=category: [
                            category_var.set(value),
                            show_category_apps(value, frame, search_entry.get())
                        ])
    
    # تحديث زر إضافة تطبيق
    add_app_btn.config(text=translations[current_language]["add_app"])
    
    # تحديث عرض التطبيقات
    current_category = category_var.get()
    show_category_apps(current_category, frame, search_entry.get())

def enable_dark_mode():
    try:
        # Main window and frames
        root.configure(bg="#2C2F38")
        header_frame.configure(bg="#1F2329")
        menu_frame.configure(bg="#1F2329")
        main_frame.configure(bg="#2C2F38")
        frame.configure(bg="#2C2F38")
        search_frame.configure(bg="#2C2F38")
        category_frame.configure(bg="#2C2F38")
        
        # Labels
        header_label.configure(bg="#1F2329", fg="white")
        welcome_label.configure(bg="#1F2329", fg="white")
        search_label.configure(bg="#2C2F38", fg="white")
        category_label.configure(bg="#2C2F38", fg="white")
        
        # Entry fields
        search_entry.configure(bg="#444444", fg="white", insertbackground="white")
        
        # Buttons
        for btn in [home_btn, support_btn, settings_btn, backup_btn, two_factor_btn, logout_btn, add_app_btn]:
            btn.configure(bg="#444444", fg="white")
        
        # Update all widgets in the main frame
        for widget in main_frame.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg="#2C2F38")
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label):
                        child.configure(bg="#2C2F38", fg="white")
                    elif isinstance(child, tk.Button):
                        child.configure(bg="#444444", fg="white")
                    elif isinstance(child, tk.Entry):
                        child.configure(bg="#444444", fg="white", insertbackground="white")
                    elif isinstance(child, tk.Frame):
                        child.configure(bg="#2C2F38")
                        for grandchild in child.winfo_children():
                            if isinstance(grandchild, tk.Label):
                                grandchild.configure(bg="#2C2F38", fg="white")
                            elif isinstance(grandchild, tk.Button):
                                grandchild.configure(bg="#444444", fg="white")
                            elif isinstance(grandchild, tk.Entry):
                                grandchild.configure(bg="#444444", fg="white", insertbackground="white")
        
        # Update category dropdown
        category_dropdown.configure(bg="#444444", fg="white")
        category_dropdown['menu'].configure(bg="#444444", fg="white")
        
    except Exception as e:
        print(f"Error in enable_dark_mode: {str(e)}")

def disable_dark_mode():
    try:
        # Main window and frames
        root.configure(bg="#FFFFFF")
        header_frame.configure(bg="#2089C1")
        menu_frame.configure(bg="#2089C1")
        main_frame.configure(bg="#F8FAFC")
        frame.configure(bg="#FFFFFF")
        search_frame.configure(bg="#F8FAFC")
        category_frame.configure(bg="#F8FAFC")
        
        # Labels
        header_label.configure(bg="#2089C1", fg="white")
        welcome_label.configure(bg="#2089C1", fg="white")
        search_label.configure(bg="#F8FAFC", fg="#116FA1")
        category_label.configure(bg="#F8FAFC", fg="#116FA1")
        
        # Entry fields
        search_entry.configure(bg="white", fg="#333333", insertbackground="#333333")
        
        # Buttons
        for btn in [home_btn, support_btn, settings_btn, backup_btn, two_factor_btn, logout_btn, add_app_btn]:
            btn.configure(bg="#116FA1", fg="white")
        
        # Update all widgets in the main frame
        for widget in main_frame.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg="#F8FAFC")
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label):
                        child.configure(bg="#F8FAFC", fg="#333333")
                    elif isinstance(child, tk.Button):
                        child.configure(bg="#116FA1", fg="white")
                    elif isinstance(child, tk.Entry):
                        child.configure(bg="white", fg="#333333", insertbackground="#333333")
                    elif isinstance(child, tk.Frame):
                        child.configure(bg="#F8FAFC")
                        for grandchild in child.winfo_children():
                            if isinstance(grandchild, tk.Label):
                                grandchild.configure(bg="#F8FAFC", fg="#333333")
                            elif isinstance(grandchild, tk.Button):
                                grandchild.configure(bg="#116FA1", fg="white")
                            elif isinstance(grandchild, tk.Entry):
                                grandchild.configure(bg="white", fg="#333333", insertbackground="#333333")
        
        # Update category dropdown
        category_dropdown.configure(bg="#116FA1", fg="white")
        category_dropdown['menu'].configure(bg="white", fg="#116FA1")
        
    except Exception as e:
        print(f"Error in disable_dark_mode: {str(e)}")

def apply_theme():
    try:
        if current_theme == "dark":
            enable_dark_mode()
        else:
            disable_dark_mode()
            
        # Update the display to reflect theme changes
        show_category_apps(category_var.get(), frame, search_entry.get())
        
    except Exception as e:
        print(f"Error applying theme: {str(e)}")
        messagebox.showerror(translations[current_language]["warning"], 
                           f"Error applying theme: {str(e)}")

# تحديث دوال التأثيرات الحركية
def on_enter(event):
    """تأثير عند تمرير الماوس فوق الزر"""
    button = event.widget
    original_color = button.cget('bg')
    
    # حفظ اللون الأصلي إذا لم يتم حفظه من قبل
    if not hasattr(button, '_original_color'):
        button._original_color = original_color
    
    # تغيير لون الخلفية عند تمرير الماوس
    if original_color == "#116FA1":
        button.configure(bg="#1E8BC3", cursor="hand2")  # أزرق فاتح
    elif original_color == "#FF4444":  # زر تسجيل الخروج
        button.configure(bg="#FF6666", cursor="hand2")  # أحمر فاتح
    elif original_color == "#f9f9f9":  # أزرار الواجهة
        button.configure(bg="#e0e0e0", cursor="hand2")
    
    # تكبير الخط قليلاً وإضافة تأثير ارتفاع
    current_font = button.cget("font").split()
    if len(current_font) >= 2:  # إذا كان الخط يحتوي على حجم
        size = int(current_font[1])
        new_font = (current_font[0], size + 1)
        button.configure(font=new_font)
    button.configure(relief="raised")

def on_leave(event):
    """تأثير عند مغادرة الماوس للزر"""
    button = event.widget
    
    # إعادة اللون الأصلي
    if hasattr(button, '_original_color'):
        button.configure(bg=button._original_color, cursor="")
    
    # إعادة حجم الخط الأصلي وإزالة تأثير الارتفاع
    current_font = button.cget("font").split()
    if len(current_font) >= 2:  # إذا كان الخط يحتوي على حجم
        size = int(current_font[1])
        new_font = (current_font[0], size - 1)
        button.configure(font=new_font)
    button.configure(relief="flat")

def apply_hover_effect(button):
    """تطبيق تأثيرات الحركة على الزر"""
    button.bind("<Enter>", on_enter)
    button.bind("<Leave>", on_leave)
    button.configure(relief="flat")  # جعل الزر مسطح بشكل افتراضي

# تعريف الفئة المخصصة للقائمة المنسدلة
class StyledOptionMenu(OptionMenu):
    def __init__(self, master, variable, *values, **kwargs):
        super().__init__(master, variable, *values, **kwargs)
        
        # تنسيق بسيط للقائمة
        self.config(
            bg="#116FA1",
            fg="white",
            font=('Arial', 11),
            relief="flat",
            activebackground="#1E8BC3",
            activeforeground="white",
            width=12  # عرض مناسب
        )
        
        # تنسيق القائمة المنسدلة
        self['menu'].config(
            bg="white",
            fg="#116FA1",
            font=('Arial', 11),
            relief="solid",
            borderwidth=1,
            activebackground="#1E8BC3",
            activeforeground="white"
        )
        
        # إضافة تأثيرات بسيطة
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        
    def on_enter(self, event):
        self.config(bg="#1E8BC3")
        
    def on_leave(self, event):
        self.config(bg="#116FA1")

def display_answer(answer):
    messagebox.showinfo("FAQ", answer)

def submit_issue(issue_widget):
    messagebox.showinfo("Success", "Thank you for your feedback!" if current_language == "en" else "شكراً على ملاحظاتك!")
    issue_widget.delete(1.0, tk.END)
    # Get the parent window (support window) and close it
    support_window = issue_widget.winfo_toplevel()
    support_window.destroy()

def create_backup():
    """إنشاء نسخة احتياطية من قاعدة البيانات"""
    try:
        # إنشاء مجلد النسخ الاحتياطية إذا لم يكن موجوداً
        if not os.path.exists(BACKUP_FOLDER):
            os.makedirs(BACKUP_FOLDER)
        
        # إنشاء اسم الملف مع التاريخ والوقت
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(BACKUP_FOLDER, f"user_{timestamp}.db")
        
        # نسخ قاعدة البيانات
        if os.path.exists("user.db"):
            shutil.copy2("user.db", backup_file)
            
            # حذف النسخ القديمة إذا تجاوز العدد الحد الأقصى
            cleanup_old_backups()
            
            return True, f"تم إنشاء نسخة احتياطية بنجاح: {backup_file}"
        else:
            return False, "لم يتم العثور على ملف قاعدة البيانات"
            
    except Exception as e:
        return False, f"خطأ في إنشاء النسخة الاحتياطية: {str(e)}"

def cleanup_old_backups():
    """حذف النسخ الاحتياطية القديمة عندما يتجاوز عددها الحد الأقصى"""
    try:
        if os.path.exists(BACKUP_FOLDER):
            backups = sorted([os.path.join(BACKUP_FOLDER, f) for f in os.listdir(BACKUP_FOLDER)
                            if f.startswith("user_") and f.endswith(".db")])
            
            # حذف النسخ القديمة إذا تجاوز العدد الحد الأقصى
            while len(backups) > MAX_BACKUP_COUNT:
                os.remove(backups[0])  # حذف أقدم نسخة
                backups.pop(0)
    except Exception as e:
        print(f"خطأ في تنظيف النسخ الاحتياطية القديمة: {str(e)}")

def restore_backup(backup_file):
    """استعادة قاعدة البيانات من نسخة احتياطية"""
    try:
        if not os.path.exists(backup_file):
            return False, "ملف النسخة الاحتياطية غير موجود"
            
        # إنشاء نسخة احتياطية من قاعدة البيانات الحالية قبل الاستعادة
        if os.path.exists("user.db"):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            current_backup = os.path.join(BACKUP_FOLDER, f"pre_restore_backup_{timestamp}.db")
            shutil.copy2("user.db", current_backup)
        
        # استعادة النسخة الاحتياطية
        shutil.copy2(backup_file, "user.db")
        return True, "تمت استعادة النسخة الاحتياطية بنجاح"
        
    except Exception as e:
        return False, f"خطأ في استعادة النسخة الاحتياطية: {str(e)}"

def get_available_backups():
    """الحصول على قائمة النسخ الاحتياطية المتوفرة"""
    try:
        if not os.path.exists(BACKUP_FOLDER):
            return []
            
        backups = [f for f in os.listdir(BACKUP_FOLDER)
                  if f.startswith("user_") and f.endswith(".db")]
        return sorted(backups, reverse=True)  # ترتيب من الأحدث إلى الأقدم
    except Exception:
        return []

def show_backup_window():
    """عرض نافذة إدارة النسخ الاحتياطية"""
    backup_window = Toplevel()
    backup_window.title(translations[current_language]["backup_management"])
    backup_window.geometry("500x400")
    backup_window.configure(bg="#FFFFFF")
    
    # إطار رئيسي
    main_frame = tk.Frame(backup_window, bg="#FFFFFF")
    main_frame.pack(expand=True, fill='both', padx=20, pady=20)
    
    # زر إنشاء نسخة احتياطية جديدة
    create_btn = tk.Button(main_frame,
                          text=translations[current_language]["create_new_backup"],
                          font=("Arial", 12),
                          command=lambda: handle_create_backup(),
                          bg="#116FA1",
                          fg="white")
    create_btn.pack(pady=10)
    apply_hover_effect(create_btn)
    
    # قائمة النسخ الاحتياطية المتوفرة
    tk.Label(main_frame,
             text=translations[current_language]["available_backups"],
             font=("Arial", 12, "bold"),
             bg="#FFFFFF").pack(pady=10)
    
    # إطار للقائمة مع شريط التمرير
    list_frame = tk.Frame(main_frame)
    list_frame.pack(fill='both', expand=True)
    
    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side='right', fill='y')
    
    backup_listbox = tk.Listbox(list_frame,
                               font=("Arial", 11),
                               selectmode='single',
                               yscrollcommand=scrollbar.set)
    backup_listbox.pack(side='left', fill='both', expand=True)
    
    scrollbar.config(command=backup_listbox.yview)
    
    # تحديث قائمة النسخ الاحتياطية
    def update_backup_list():
        backup_listbox.delete(0, tk.END)
        backups = get_available_backups()
        for backup in backups:
            backup_listbox.insert(tk.END, backup)
    
    # معالجة إنشاء نسخة احتياطية
    def handle_create_backup():
        success, message = create_backup()
        if success:
            messagebox.showinfo(translations[current_language]["success"], 
                              translations[current_language]["backup_created"])
            update_backup_list()
        else:
            messagebox.showerror(translations[current_language]["warning"], 
                               translations[current_language]["backup_error"])
    
    # معالجة استعادة نسخة احتياطية
    def handle_restore_backup():
        selection = backup_listbox.curselection()
        if not selection:
            messagebox.showwarning(translations[current_language]["warning"], 
                                 translations[current_language]["select_backup"])
            return
            
        backup_file = backup_listbox.get(selection[0])
        if messagebox.askyesno(translations[current_language]["confirm"], 
                             translations[current_language]["restore_confirm"]):
            success, message = restore_backup(os.path.join(BACKUP_FOLDER, backup_file))
            if success:
                messagebox.showinfo(translations[current_language]["success"], 
                                  translations[current_language]["restore_success"])
                backup_window.destroy()
                # إعادة تشغيل التطبيق
                root.destroy()
                os.execl(sys.executable, sys.executable, *sys.argv)
            else:
                messagebox.showerror(translations[current_language]["warning"], 
                                   translations[current_language]["restore_error"])
    
    # زر استعادة النسخة الاحتياطية
    restore_btn = tk.Button(main_frame,
                           text=translations[current_language]["restore_selected"],
                           font=("Arial", 12),
                           command=handle_restore_backup,
                           bg="#116FA1",
                           fg="white")
    restore_btn.pack(pady=10)
    apply_hover_effect(restore_btn)
    
    # تحديث القائمة عند فتح النافذة
    update_backup_list()

def show_two_factor_settings():
    """عرض نافذة إعدادات المصادقة الثنائية"""
    settings_window = Toplevel()
    settings_window.title(translations[current_language]["two_factor_settings"])
    settings_window.geometry("400x500")
    settings_window.configure(bg="#FFFFFF")
    
    # Main container
    main_container = tk.Frame(settings_window, bg="#FFFFFF")
    main_container.pack(expand=True, fill='both', padx=40, pady=20)
    
    # Title
    title_label = tk.Label(main_container,
                          text=translations[current_language]["two_factor_settings"],
                          font=("Arial", 20, "bold"),
                          bg="#FFFFFF",
                          fg="#116FA1")
    title_label.pack(pady=(0, 30))
    
    # Check if PIN is already set up
    has_pin = check_pin_setup()
    
    if has_pin:
        # Show disable button if PIN is set up
        disable_btn = tk.Button(main_container,
                              text=translations[current_language]["disable_2fa"],
                              font=("Arial", 14, "bold"),
                              command=lambda: disable_2fa(settings_window),
                              bg="#FF4444",
                              fg="white",
                              width=20)
        disable_btn.pack(pady=20)
        apply_hover_effect(disable_btn)
        
        # Add change PIN option
        change_pin_btn = tk.Button(main_container,
                                 text=translations[current_language]["pin_reset"],
                                 font=("Arial", 14, "bold"),
                                 command=lambda: show_pin_setup_window(lambda: settings_window.destroy()),
                                 bg="#116FA1",
                                 fg="white",
                                 width=20)
        change_pin_btn.pack(pady=20)
        apply_hover_effect(change_pin_btn)
    else:
        # Show enable button if PIN is not set up
        enable_btn = tk.Button(main_container,
                             text=translations[current_language]["enable_2fa"],
                             font=("Arial", 14, "bold"),
                             command=lambda: show_pin_setup_window(lambda: settings_window.destroy()),
                             bg="#116FA1",
                             fg="white",
                             width=20)
        enable_btn.pack(pady=20)
        apply_hover_effect(enable_btn)

def disable_2fa(settings_window):
    """تعطيل المصادقة الثنائية"""
    if messagebox.askyesno(translations[current_language]["confirm"],
                          translations[current_language]["disable_2fa"] + "?"):
        db, cursor = init_pin_database()
        if not db:
            return
            
        try:
            cursor.execute("""
                DELETE FROM user_pins
                WHERE username = ?
            """, (current_user,))
            db.commit()
            
            messagebox.showinfo(translations[current_language]["success"],
                              translations[current_language]["disable_2fa"])
            settings_window.destroy()
                
        except Exception as e:
            messagebox.showerror(translations[current_language]["warning"],
                               translations[current_language]["pin_error"])
        finally:
            db.close()

# Add before the Main Window section
def create_pin_button(parent, text, command):
    """Create a styled PIN button"""
    btn = tk.Button(parent,
                    text=text,
                    font=("Arial", 14, "bold"),
                    width=3,
                    height=1,
                    command=command,
                    bg="#116FA1",
                    fg="white",
                    relief="flat")
    apply_hover_effect(btn)
    return btn

def show_pin_setup_window(after_setup_callback=None):
    """Show PIN setup window"""
    setup_window = Toplevel()
    setup_window.title(translations[current_language]["pin_setup"])
    setup_window.geometry("400x600")
    setup_window.configure(bg="#FFFFFF")
    
    # Main container
    main_container = tk.Frame(setup_window, bg="#FFFFFF")
    main_container.pack(expand=True, fill='both', padx=40, pady=20)
    
    # Title
    title_label = tk.Label(main_container,
                          text=translations[current_language]["pin_setup"],
                          font=("Arial", 20, "bold"),
                          bg="#FFFFFF",
                          fg="#116FA1")
    title_label.pack(pady=(0, 20))
    
    # Rules
    rules_label = tk.Label(main_container,
                          text=translations[current_language]["pin_rules"],
                          font=("Arial", 12),
                          bg="#FFFFFF",
                          fg="#666666",
                          wraplength=300)
    rules_label.pack(pady=(0, 20))
    
    # PIN entry
    pin_var = StringVar()
    pin_entry = tk.Entry(main_container,
                        textvariable=pin_var,
                        font=("Arial", 24),
                        justify='center',
                        show="•",
                        width=6)
    pin_entry.pack(pady=10)
    
    # Confirm PIN entry
    confirm_var = StringVar()
    confirm_entry = tk.Entry(main_container,
                           textvariable=confirm_var,
                           font=("Arial", 24),
                           justify='center',
                           show="•",
                           width=6)
    confirm_entry.pack(pady=10)
    
    # Number pad frame
    pad_frame = tk.Frame(main_container, bg="#FFFFFF")
    pad_frame.pack(pady=20)
    
    def add_digit(digit, entry):
        if len(entry.get()) < 6:
            entry.insert(tk.END, str(digit))
            
    def remove_digit(entry):
        if len(entry.get()) > 0:
            entry.delete(len(entry.get())-1, tk.END)
    
    # Create number pad
    current_entry = pin_entry
    for i in range(9):
        row = i // 3
        col = i % 3
        btn = create_pin_button(pad_frame, str(i+1),
                              lambda d=i+1: add_digit(d, current_entry))
        btn.grid(row=row, column=col, padx=5, pady=5)
    
    # Add 0 and backspace buttons
    zero_btn = create_pin_button(pad_frame, "0",
                               lambda: add_digit(0, current_entry))
    zero_btn.grid(row=3, column=1, padx=5, pady=5)
    
    back_btn = create_pin_button(pad_frame, "⌫",
                               lambda: remove_digit(current_entry))
    back_btn.grid(row=3, column=2, padx=5, pady=5)
    
    # Switch between PIN and confirm entries
    def switch_entry():
        nonlocal current_entry
        if current_entry == pin_entry:
            if len(pin_var.get()) == 6:
                current_entry = confirm_entry
                confirm_entry.focus()
    
    pin_entry.bind('<KeyRelease>', lambda e: switch_entry())
    
    def save_pin():
        pin = pin_var.get()
        confirm = confirm_var.get()
        
        if pin != confirm:
            messagebox.showerror(translations[current_language]["warning"],
                               translations[current_language]["pin_mismatch"])
            return
            
        if not is_valid_pin(pin):
            messagebox.showerror(translations[current_language]["warning"],
                               translations[current_language]["pin_invalid"])
            return
            
        # Save PIN to database
        db, cursor = init_pin_database()
        if not db:
            return
            
        try:
            pin_hash = hash_pin(pin)
            cursor.execute("""
                INSERT INTO user_pins (username, pin_hash, failed_attempts)
                VALUES (?, ?, 0)
                ON CONFLICT(username) DO UPDATE SET
                pin_hash = ?, failed_attempts = 0
            """, (current_user, pin_hash, pin_hash))
            db.commit()
            
            messagebox.showinfo(translations[current_language]["success"],
                              translations[current_language]["pin_success"])
            setup_window.destroy()
            
            if after_setup_callback:
                after_setup_callback()
                
        except Exception as e:
            messagebox.showerror(translations[current_language]["warning"],
                               translations[current_language]["pin_error"])
        finally:
            db.close()
    
    # Save button
    save_btn = tk.Button(main_container,
                        text=translations[current_language]["save"],
                        font=("Arial", 14, "bold"),
                        command=save_pin,
                        bg="#116FA1",
                        fg="white",
                        width=20)
    save_btn.pack(pady=20)
    apply_hover_effect(save_btn)

def show_pin_verification_window(after_verify_callback):
    """Show PIN verification window"""
    if not check_pin_attempts(current_user):
        messagebox.showerror(translations[current_language]["warning"],
                           translations[current_language]["pin_attempts"])
        return
        
    verify_window = Toplevel()
    verify_window.title(translations[current_language]["pin_verify"])
    verify_window.geometry("400x600")
    verify_window.configure(bg="#FFFFFF")
    
    # Main container
    main_container = tk.Frame(verify_window, bg="#FFFFFF")
    main_container.pack(expand=True, fill='both', padx=40, pady=20)
    
    # Title
    title_label = tk.Label(main_container,
                          text=translations[current_language]["pin_verify"],
                          font=("Arial", 20, "bold"),
                          bg="#FFFFFF",
                          fg="#116FA1")
    title_label.pack(pady=(0, 20))
    
    # PIN entry
    pin_var = StringVar()
    pin_entry = tk.Entry(main_container,
                        textvariable=pin_var,
                        font=("Arial", 24),
                        justify='center',
                        show="•",
                        width=6)
    pin_entry.pack(pady=20)
    
    # Number pad frame
    pad_frame = tk.Frame(main_container, bg="#FFFFFF")
    pad_frame.pack(pady=20)
    
    def add_digit(digit):
        if len(pin_entry.get()) < 6:
            pin_entry.insert(tk.END, str(digit))
            
    def remove_digit():
        if len(pin_entry.get()) > 0:
            pin_entry.delete(len(pin_entry.get())-1, tk.END)
    
    # Create number pad
    for i in range(9):
        row = i // 3
        col = i % 3
        btn = create_pin_button(pad_frame, str(i+1),
                              lambda d=i+1: add_digit(d))
        btn.grid(row=row, column=col, padx=5, pady=5)
    
    # Add 0 and backspace buttons
    zero_btn = create_pin_button(pad_frame, "0",
                               lambda: add_digit(0))
    zero_btn.grid(row=3, column=1, padx=5, pady=5)
    
    back_btn = create_pin_button(pad_frame, "⌫",
                               remove_digit)
    back_btn.grid(row=3, column=2, padx=5, pady=5)
    
    def verify_pin():
        pin = pin_var.get()
        
        db, cursor = init_pin_database()
        if not db:
            return
            
        try:
            cursor.execute("""
                SELECT pin_hash FROM user_pins
                WHERE username = ?
            """, (current_user,))
            result = cursor.fetchone()
            
            if not result:
                messagebox.showerror(translations[current_language]["warning"],
                                   translations[current_language]["pin_error"])
                return
                
            pin_hash = result[0]
            if verify_pin(pin_hash, pin):
                update_pin_attempts(current_user, True)
                verify_window.destroy()
                after_verify_callback()
            else:
                update_pin_attempts(current_user, False)
                messagebox.showerror(translations[current_language]["warning"],
                                   translations[current_language]["pin_incorrect"])
                pin_var.set("")
                
        except Exception as e:
            messagebox.showerror(translations[current_language]["warning"],
                               translations[current_language]["pin_error"])
        finally:
            db.close()
    
    # Verify button
    verify_btn = tk.Button(main_container,
                          text=translations[current_language]["confirm"],
                          font=("Arial", 14, "bold"),
                          command=verify_pin,
                          bg="#116FA1",
                          fg="white",
                          width=20)
    verify_btn.pack(pady=20)
    apply_hover_effect(verify_btn)

def handle_forgot_pin(parent_window):
    """Handle forgot PIN process"""
    # Show password verification window
    password_window = Toplevel()
    password_window.title(translations[current_language]["pin_reset"])
    password_window.geometry("400x200")
    password_window.configure(bg="#FFFFFF")
    
    main_frame = tk.Frame(password_window, bg="#FFFFFF")
    main_frame.pack(expand=True, fill='both', padx=20, pady=20)
    
    tk.Label(main_frame,
            text=translations[current_language]["enter_password"],
            font=("Arial", 12),
            bg="#FFFFFF").pack(pady=10)
    
    password_var = StringVar()
    password_entry = tk.Entry(main_frame,
                            textvariable=password_var,
                            font=("Arial", 12),
                            show="*")
    password_entry.pack(pady=10)
    
    def verify_password():
        # Here you would verify the master password
        # If correct, close current windows and show PIN setup
        password_window.destroy()
        parent_window.destroy()
        show_pin_setup_window()
    
    verify_btn = tk.Button(main_frame,
                          text=translations[current_language]["confirm"],
                          font=("Arial", 12),
                          command=verify_password,
                          bg="#116FA1",
                          fg="white")
    verify_btn.pack(pady=10)
    apply_hover_effect(verify_btn)

# Add this function before the Main Window section
def check_pin_setup():
    """Check if PIN is set up for current user"""
    db, cursor = init_pin_database()
    if not db:
        return False
        
    try:
        cursor.execute("""
            SELECT pin_hash FROM user_pins
            WHERE username = ?
        """, (current_user,))
        return cursor.fetchone() is not None
    finally:
        db.close()

# Modify the login process
def handle_login():
    """Handle the login process"""
    # First, verify username and password
    # ... (your existing login verification code)
    
    def after_pin_verify():
        # Continue with normal login process
        show_main_window()
    
    def after_pin_setup():
        # Show verification window after setup
        show_pin_verification_window(after_pin_verify)
    
    # Check if PIN is set up
    if check_pin_setup():
        # If PIN exists, show verification window
        show_pin_verification_window(after_pin_verify)
    else:
        # If no PIN, show setup window
        show_pin_setup_window(after_pin_setup)

def login(pin_entry):
    pin = pin_entry.get()
    if not pin:
        messagebox.showerror("Error", "Please enter a PIN")
        return

    cursor.execute("SELECT pin_hash FROM user_pin WHERE id = 1")
    result = cursor.fetchone()
    
    if not result:
        # First time setup
        pin_hash = hash_pin(pin)
        cursor.execute("INSERT INTO user_pin (id, pin_hash) VALUES (1, ?)", (pin_hash,))
        conn.commit()
        show_main_window()
    else:
        stored_hash = result[0]
        if verify_pin(stored_hash, pin):
            show_main_window()
        else:
            messagebox.showerror("Error", "Incorrect PIN")
            pin_entry.delete(0, tk.END)

def switch_password(password_entry, show_var):
    """Toggle password visibility"""
    if password_entry['show'] == '*':
        password_entry.config(show='')
        show_var.set("🔒")
    else:
        password_entry.config(show='*')
        show_var.set("👁")

def check_password(password):
    """Check password strength and return appropriate message and color"""
    if len(password) < 8:
        return translations[current_language]["password_strength"]["Weak"], "red"
    elif len(password) < 12:
        return translations[current_language]["password_strength"]["Medium"], "orange"
    else:
        return translations[current_language]["password_strength"]["Strong"], "green"

def copy_to_clipboard(text):
    """Copy text to clipboard and show confirmation"""
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()
    messagebox.showinfo(translations[current_language]["success"], 
                       translations[current_language]["copy_success"])

def change_bottun(app_name, strength_label):
    """Handle password change for an app"""
    change_window = Toplevel()
    change_window.title(translations[current_language]["change_password_for"] + " " + app_name)
    change_window.geometry("400x200")
    change_window.configure(bg="#FFFFFF")
    
    # Password entry frame
    entry_frame = tk.Frame(change_window, bg="#FFFFFF")
    entry_frame.pack(pady=20)
    
    password_entry = tk.Entry(entry_frame, font=("Arial", 12), show="*")
    password_entry.pack(side="left", padx=5)
    
    # Generate button
    generate_btn = tk.Button(entry_frame, 
                           text=translations[current_language]["generate"],
                           command=lambda: generate_bottun(password_entry))
    generate_btn.pack(side="left", padx=5)
    apply_hover_effect(generate_btn)
    
    def save_new_password():
        new_password = password_entry.get()
        
        if len(new_password) < 8:
            messagebox.showwarning(translations[current_language]["warning"],
                                 translations[current_language]["password_length"])
            return
            
        try:
            db = sqlite3.connect("user.db")
            cursor = db.cursor()
            
            # Get master key
            master_key = get_master_key()
            if not master_key:
                raise Exception("Failed to retrieve master key")
                
            # Encrypt the new password
            encrypted_password = encrypt_password(new_password, master_key)
            if not encrypted_password:
                raise Exception("Failed to encrypt password")
                
            # Update the password
            cursor.execute("""
                UPDATE apps 
                SET encrypted_password = ?
                WHERE username = ? AND app_name = ?
            """, (encrypted_password, current_user, app_name))
            
            db.commit()
        # Update strength label
            strength_text, strength_color = check_password(new_password)
            strength_label.config(text=strength_text, fg=strength_color)
            
            messagebox.showinfo(translations[current_language]["success"],
                              translations[current_language]["password_changed"])
            change_window.destroy()
            
        except Exception as e:
            messagebox.showerror(translations[current_language]["warning"],
                               f"{translations[current_language]['db_error']}: {str(e)}")
        finally:
            if 'db' in locals():
                db.close()
    
    # Save button
    save_btn = tk.Button(change_window,
                        text=translations[current_language]["save"],
                        command=save_new_password)
    save_btn.pack(pady=20)
    apply_hover_effect(save_btn)

            
            
# Main Window
root = tk.Tk()
root.title(translations[current_language]["title"])

root.geometry("1000x700")
root.configure(bg="#FFFFFF")
#root.attributes('-fullscreen', True)
#root.iconbitmap("icono.ico")
root.state('zoomed')


# Initialize application before creating UI
if not initialize_application():
    messagebox.showerror("Error", "Failed to initialize application. Please check database connection.")
    root.destroy()
    sys.exit(1)

# Header with title and welcome message
header_frame = tk.Frame(root, bg="#2089C1", height=100)
header_frame.pack(side="top", fill="x")

header_label = tk.Label(header_frame, text=translations[current_language]["title"], 
                       font=("Arial", 24, "bold"), bg="#2089C1", fg="light gray")
header_label.pack(pady=10)

welcome_label = tk.Label(header_frame, text=translations[current_language]["welcome"], 
                        font=("Arial", 14), bg="#2089C1", fg="light gray")
welcome_label.pack()

# Menu frame (sidebar)
menu_frame = tk.Frame(root, bg="#2089C1", width=200)
menu_frame.pack(side="left", fill="y")

home_btn = HoverButton(menu_frame, text=translations[current_language]["home"], 
                    bg="#116FA1", fg="white", font=("Arial", 12),
                    activebackground="#3D3BF3", width=20)
home_btn.pack(fill="x", pady=5)

support_btn = HoverButton(menu_frame, text=translations[current_language]["support"], 
                       bg="#116FA1", fg="white", font=("Arial", 12),
                       activebackground="#3D3BF3", width=20, 
                       command=open_support_window)
support_btn.pack(fill="x", pady=5)

settings_btn = HoverButton(menu_frame, text=translations[current_language]["settings"], 
                        bg="#116FA1", fg="white", font=("Arial", 12),
                        activebackground="#3D3BF3", width=20, 
                        command=open_settings_window)
settings_btn.pack(fill="x", pady=5)

# Backup button
backup_btn = HoverButton(menu_frame, text=translations[current_language]["backup"],
                        bg="#116FA1", fg="white", font=("Arial", 12),
                        activebackground="#3D3BF3", width=20,
                        command=show_backup_window)
backup_btn.pack(fill="x", pady=5)

# Two-Factor Authentication button
two_factor_btn = HoverButton(menu_frame, text=translations[current_language]["two_factor_auth"],
                           bg="#116FA1", fg="white", font=("Arial", 12),
                           activebackground="#3D3BF3", width=20,
                           command=show_two_factor_settings)
two_factor_btn.pack(fill="x", pady=5)

# Logout button
logout_btn = HoverButton(menu_frame, text=translations[current_language]["logout"],
                        bg="#116FA1", fg="white", font=("Arial", 12),
                        activebackground="#3D3BF3", width=20,
                        command=logout_user)
logout_btn.pack(fill="x", pady=5)

# Main content frame
main_frame = tk.Frame(root, bg="#F8FAFC")
main_frame.pack(side="right", fill="both", expand=True)

# Search and Categories frame
search_frame = tk.Frame(main_frame, bg="#F8FAFC")
search_frame.pack(pady=10, padx=20, fill="x")

search_label = tk.Label(search_frame, 
                       text=translations[current_language]["search"],
                       font=("Arial", 12, "bold"),
                       bg="#F8FAFC",
                       fg="#116FA1")
search_label.pack(side="left", padx=(0, 10))

search_entry = tk.Entry(search_frame,
                       font=("Arial", 12),
                       relief="flat",
                       bg="white",
                       fg="#333333",
                       highlightthickness=1,
                       highlightbackground="#CCCCCC",
                       highlightcolor="#116FA1")
search_entry.pack(side="left", fill="x", expand=True, padx=5)

# Category frame
category_frame = tk.Frame(main_frame, bg="#F8FAFC")
category_frame.pack(pady=10, padx=20, fill="x")

category_label = tk.Label(category_frame,
                         text=translations[current_language]["select_category"],
                         font=("Arial", 12, "bold"),
                         bg="#F8FAFC",
                         fg="#116FA1")
category_label.pack(side="left", padx=(0, 10))

category_var = StringVar(category_frame)
category_var.set(translations[current_language]["categories"][0])

category_dropdown = StyledOptionMenu(category_frame,
                                   category_var,
                                   *translations[current_language]["categories"])
category_dropdown.pack(pady=10)

# Frame for displaying apps
frame = tk.Frame(main_frame, bg="#EEEEEE", relief="solid", bd=1)
frame.pack(pady=20, padx=20, fill="both", expand=True)

# Add New Application button
add_app_btn = tk.Button(main_frame, 
                       text=translations[current_language]["add_app"],
                       font=("Arial", 14),
                       command=show_new_apps_window,
                       bg="#116FA1",
                       fg="white")
add_app_btn.pack(pady=20)

# Bind events
category_var.trace("w", lambda *args: show_category_apps(category_var.get(), frame, search_entry.get()))
search_entry.bind("<KeyRelease>", lambda event: show_category_apps(category_var.get(), frame, search_entry.get()))

# Apply hover effects
apply_hover_effect(home_btn)
apply_hover_effect(support_btn)
apply_hover_effect(settings_btn)
apply_hover_effect(backup_btn)
apply_hover_effect(two_factor_btn)
apply_hover_effect(logout_btn)
apply_hover_effect(add_app_btn)

# Initialize display
show_category_apps(category_var.get(), frame)

# Start the application
root.mainloop() 

def show_main_window():
    pass


