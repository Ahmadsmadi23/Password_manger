import tkinter as tk
import subprocess
import sqlite3
from argon2 import PasswordHasher
import re
from datetime import datetime, timedelta
import sys

# Language translations
translations = {
    'en': {
        'title': 'Welcome to secure vault',
        'username': 'Username',
        'password': 'Password',
        'login': 'Login',
        'forgot_password': 'Forgot password?',
        'no_account': "Don't have an account? ",
        'register': 'Register',
        'error': 'Incorrect entry',
        'blocked': '🚫 You have been temporarily blocked for 5 sacnd ',
        'try_again': '✅ You can try again'
    },
    'ar': {
        'title': 'مرحباً بك في الخزنة الآمنة',
        'username': 'اسم المستخدم',
        'password': 'كلمة المرور',
        'login': 'تسجيل الدخول',
        'forgot_password': 'نسيت كلمة المرور؟',
        'no_account': 'ليس لديك حساب؟ ',
        'register': 'تسجيل',
        'error': 'إدخال غير صحيح',
        'blocked': '🚫 تم حظرك مؤقتاً لمدة 5 ثواني ',
        'try_again': '✅ يمكنك المحاولة مرة أخرى'
    }
}

current_language = 'en'  # Default language

# Remove all JSON and database login attempts code
# Instead, add this at the start of the file (after imports)
login_attempts = {}  # Dictionary to store attempts in memory


# نافذة 
Root_frame = tk.Tk()
Root_frame.title("Login")


# Center Root_frame on screen
Root_frame_width = 600
Root_frame_height = 550
screen_width = Root_frame.winfo_screenwidth()
screen_height = Root_frame.winfo_screenheight()
x = (screen_width - Root_frame_width) // 2
y = (screen_height - Root_frame_height) // 2
Root_frame.geometry(f"{Root_frame_width}x{Root_frame_height}+{x}+{y}")


Root_frame.config(bg="#2C5364")
Root_frame.minsize(500, 600)
#Root_frame.maxsize(500, 600)
#Root_frame.iconbitmap("icono.ico")
# الخطوط
header_font = ("Arial", 28, "bold")  # Larger font
text_font = ("Arial", 14)  # Larger font
button_font = ("Arial", 16, "bold")  # Larger font

# Create language frame at the top right
language_frame = tk.Frame(Root_frame, bg="#2C5364")
language_frame.pack(anchor="e", padx=20, pady=(10, 0))

# Function to change language
def change_language():
    global current_language
    current_language = 'ar' if current_language == 'en' else 'en'
    update_language()
    # Update language indicator
    if current_language == 'en':
        language_indicator.config(text="عربي")
    else:
        language_indicator.config(text="English")

def update_language():
    header_label.config(text=translations[current_language]['title'])
    username_label.config(text=translations[current_language]['username'])
    password_label.config(text=translations[current_language]['password'])
    login_button.config(text=translations[current_language]['login'])
    forgot_password.config(text=translations[current_language]['forgot_password'])
    register_link.config(text=translations[current_language]['register'])
    no_account_label.config(text=translations[current_language]['no_account'])

# Language switcher with globe icon and indicator
globe_label = tk.Label(
    language_frame, 
    text="🌐", 
    font=("Arial", 14), 
    bg="#2C5364", 
    fg="white",
    cursor="hand2"
)
globe_label.pack(side="left")

language_indicator = tk.Label(
    language_frame,
    text="عربي",  # Default text when in English mode
    font=("Arial", 8),
    bg="#2C5364",
    fg="white",
    cursor="hand2"
)
language_indicator.pack(side="left", padx=(5, 0))

# Bind click events to both the globe and the text
globe_label.bind("<Button-1>", lambda e: change_language())
language_indicator.bind("<Button-1>", lambda e: change_language())

# عنوان  
header_label = tk.Label(Root_frame, text=translations[current_language]['title'], font=header_font, bg="#2C5364", fg="white")
header_label.pack(pady=(30, 30))  # Increased padding

# إطار  
frame = tk.Frame(Root_frame, bg="#0F2027", padx=30, pady=30)  # Increased padding
frame.pack(pady=20)

# Add after imports
ph = PasswordHasher()

#التحقق من مدخلات المستخدم في خانه اليوزر نيم 
def validate_username(char):
    # منع الأحرف الخاصة التي يمكن استخدامها في SQL Injection
    # السماح فقط بالأحرف الإنجليزية والأرقام والشرطة
    return bool(re.match(r'^[a-zA-Z0-9-]+$', char) if char else True)

def sanitize_username(username):
    # تنظيف اسم المستخدم من أي أحرف غير آمنة
    return re.sub(r'[^a-zA-Z0-9-]', '', username)

#التحقق من خانه الباسورد 
def validate_password(char):
    # Allow all characters except Arabic
    return bool(re.match(r'^[a-zA-Z0-9@#$%^&*()_+=\-\[\]{}|\\:;"\'<>,.?/~`]+$', char) if char else True)

#استدعا الفنكشن 
username_validation = Root_frame.register(validate_username)
password_validation = Root_frame.register(validate_password)


# اسم المستخدم
username_label = tk.Label(frame, text=translations[current_language]['username'], font=text_font, bg="#0F2027", fg="white")
username_label.grid(row=0, column=0, sticky="w", pady=(10, 5))
username_entry = tk.Entry(frame, font=text_font, width=30,validate="key", validatecommand=(username_validation, '%S'))
username_entry.grid(row=1, column=0, padx=10, pady=5)

# Move the toggle_password function before the password container setup
def toggle_password():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        show_password_btn.config(text='🔒')
    else:
        password_entry.config(show='*')
        show_password_btn.config(text='👁')

# Then create the password container and its components
password_label = tk.Label(frame, text=translations[current_language]['password'], font=text_font, bg="#0F2027", fg="white")
password_label.grid(row=2, column=0, sticky="w", pady=(10, 5))

password_entry = tk.Entry(
    frame,  # Changed from password_container to frame
    font=text_font, 
    show="*", 
    width=30,  # Match username width
    validate="key",
    validatecommand=(password_validation, '%S')
)
password_entry.grid(row=3, column=0, padx=10, pady=5)  # Use grid like username

show_password_btn = tk.Button(frame, text="👁", font=text_font, bg="#0F2027", fg="#3498db", bd=0, 
                              activebackground="#0F2027", activeforeground="#2980b9", cursor="hand2", command=toggle_password
)
show_password_btn.grid(row=3, column=1, sticky="w")  # Place button next to entry


result_label = tk.Label(frame, text="")
result_label.grid(row=5, column=0, pady=(5, 10))

# رسالة الخطأ
error_label = tk.Label(frame, text="", font=text_font, bg="#0F2027", fg="#ff3333")
error_label.grid(row=5, column=0, pady=(5, 10))

def show_error(message=None):
    if message is None:
        message = translations[current_language]['error']
    error_label.config(text=message)
    forgot_password.grid()
    Root_frame.after(2000, lambda: error_label.config(text=""))

#فنكشن لعمل بلوك لمده 30 ثانيه بعد خامس دحول خاطئ من المستخدم
def enable_entries():
    username_entry.config(state='normal')
    password_entry.config(state='normal')
    result_label.config(text=translations[current_language]['try_again'])
    # إعادة تعيين عدد المحاولات
    if username_entry.get() in login_attempts:
        login_attempts[username_entry.get()]['count'] = 0

# دالة التحقق من المحاولات
def check_login_attempts(username):
    current_time = datetime.now()
    
    if username in login_attempts:
        attempts = login_attempts[username]
        # إذا مرت 30 ثانية منذ آخر محاولة، نعيد العد
        if (current_time - attempts['last_attempt']) > timedelta(seconds=30):
            attempts['count'] = 0
            attempts['last_attempt'] = current_time
            return True
        
        attempts['last_attempt'] = current_time
        attempts['count'] += 1
        
        # إذا وصل عدد المحاولات إلى 5، نقوم بالحظر
        if attempts['count'] >= 5:
            # نقوم بتعطيل الحقول
            username_entry.config(state='disabled')
            password_entry.config(state='disabled')
            result_label.config(text=translations[current_language]['blocked'])
            
            # مؤقت لإعادة التمكين بعد 30 ثانية
            Root_frame.after(30000, enable_entries)
            return False
    else:
        login_attempts[username] = {'count': 1, 'last_attempt': current_time}
    return True


def reset_login_attempts(username):
    if username in login_attempts:
        del login_attempts[username]  # Remove the entry completely on successful login

def open_main_Root_frame():
    # الحصول على اسم المستخدم وتنظيفه
    username = sanitize_username(username_entry.get().strip())
    password = password_entry.get()
    
    #اذا كان المستخد او الباسورد غير موجود في الداتا بطلع عنا ايرر 
    if not username or not password:
        show_error()
        return
    
    #يستخدم الفنكشن  عشان يعمل بلوك للمستخدم 
    if not check_login_attempts(username):
        result_label.config(text=translations[current_language]['blocked'])
        username_entry.config(state='disabled')
        password_entry.config(state='disabled')

        # مؤقت يعيد التمكين بعد 40 ثانيه  (1800 ثانية)
        Root_frame.after(10000, enable_entries)  # بعد 10 ثواني فقط

        return
    
    try:
        conn = sqlite3.connect('user.db')
        cursor = conn.cursor()
        
        # استخدام المعاملات المُعدة مسبقاً لمنع SQL Injection
        cursor.execute("SELECT password FROM user WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result:
            stored_hash = result[0]
            try:
                ph.verify(stored_hash, password.encode())
                log_login_attempt(username, True)
                reset_login_attempts(username)
                Root_frame.destroy()
                subprocess.Popen([sys.executable, "Face2.py", username])
            except:
                log_login_attempt(username, False)
                show_error()
                username_entry.delete(0, tk.END)
                password_entry.delete(0, tk.END)
                username_entry.focus()
        else:
            log_login_attempt(username, False)
            show_error()
            username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
            username_entry.focus()
            
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # للتصحيح
        show_error()
    except Exception as e:
        print(f"Error: {e}")  # للتصحيح
        show_error()

# زر تسجيل الدخول
login_button = tk.Button(
    frame,
    text=translations[current_language]['login'],
    font=button_font,
    bg="#3498db",
    fg="white",
    padx=15,  # Increased padding
    pady=8,   # Increased padding
    relief="flat",
    command=open_main_Root_frame
)
login_button.grid(row=6, column=0, pady=(20, 10))

# Bind Enter key to login
username_entry.bind('<Return>', lambda e: password_entry.focus())
password_entry.bind('<Return>', lambda e: open_main_Root_frame())

# Add after the login button
forgot_password = tk.Label(frame,text=translations[current_language]['forgot_password'],font=text_font,bg="#0F2027",fg="#3498db",cursor="hand2")
forgot_password.grid(row=4, column=0, pady=(5, 10))
forgot_password.grid_remove()  # Initially hidden
forgot_password.bind("<Button-1>", lambda e: [Root_frame.destroy(), subprocess.Popen([sys.executable, "resetpasswored.py"])])

# Add after forgot password
register_frame = tk.Frame(frame, bg="#0F2027")
register_frame.grid(row=7, column=0, pady=(0, 10))

no_account_label = tk.Label(register_frame, text=translations[current_language]['no_account'], 
                          font=text_font, bg="#0F2027", fg="white")
no_account_label.pack(side="left")

register_link = tk.Label(register_frame, text=translations[current_language]['register'],
                        font=text_font, bg="#0F2027", fg="#3498db", cursor="hand2")
register_link.pack(side="left")
register_link.bind("<Button-1>", lambda e: [Root_frame.destroy(), subprocess.Popen([sys.executable, "Register.py"])])

def create_db():
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        security_question TEXT NOT NULL,
        security_answer TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

# Add after imports
def setup_database():
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    
    # Create login attempts table if not exists
    cursor.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        attempt_time TIMESTAMP,
        ip_address TEXT,
        success BOOLEAN
    )''')
    
    conn.commit()
    return conn, cursor

def log_login_attempt(username, success):
    """تسجيل محاولة الدخول في قاعدة البيانات"""
    try:
        conn = sqlite3.connect('user.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO login_attempts (username, attempt_time, success)
            VALUES (?, ?, ?)
        """, (username, datetime.now(), success))
        
        conn.commit()
    except Exception as e:
        print(f"Error logging login attempt: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

def get_login_attempts(username):
    """الحصول على محاولات الدخول السابقة"""
    try:
        conn = sqlite3.connect('user.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT attempt_time, success 
            FROM login_attempts 
            WHERE username = ? 
            ORDER BY attempt_time DESC 
            LIMIT 5
        """, (username,))
        
        return cursor.fetchall()
    except Exception as e:
        print(f"Error getting login attempts: {e}")
        return []
    finally:
        if 'conn' in locals():
            conn.close()

def check_login_attempts(username):
    """التحقق من محاولات الدخول"""
    attempts = get_login_attempts(username)
    if not attempts:
        return True
        
    # التحقق من آخر 5 محاولات
    failed_attempts = sum(1 for attempt in attempts if not attempt[1])
    if failed_attempts >= 5:
        last_attempt = datetime.fromisoformat(attempts[0][0])
        if datetime.now() - last_attempt < timedelta(minutes=30):
            return False
    return True

# Add at the end before mainloop
create_db()
setup_database()

Root_frame.mainloop()
