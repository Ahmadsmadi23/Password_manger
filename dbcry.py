import os
import sys
import secrets
import sqlite3
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# إعداد المسارات
APP_DIR = os.path.join(os.path.dirname(__file__), ".appdata")
KEY_FILE = os.path.join(APP_DIR, "dbkey.txt")
DB_FILE = "user.db"
ENC_DB_FILE = os.path.join(APP_DIR, "user.db.enc")

# توليد أو قراءة مفتاح التشفير

def get_or_create_db_key():
    if not os.path.exists(APP_DIR):
        os.makedirs(APP_DIR)
    if not os.path.exists(KEY_FILE):
        key = secrets.token_bytes(32)  # 256-bit key
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

# دوال التشفير وفك التشفير للملف بالكامل

def encrypt_file(input_file, output_file, key):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    with open(input_file, "rb") as f:
        data = f.read()
    ct = aesgcm.encrypt(nonce, data, None)
    with open(output_file, "wb") as f:
        f.write(nonce + ct)

def decrypt_file(input_file, output_file, key):
    with open(input_file, "rb") as f:
        file_data = f.read()
    nonce = file_data[:12]
    ct = file_data[12:]
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ct, None)
    with open(output_file, "wb") as f:
        f.write(data)

# فك تشفير قاعدة البيانات عند بدء التطبيق

def prepare_database():
    key = get_or_create_db_key()
    if os.path.exists(ENC_DB_FILE):
        decrypt_file(ENC_DB_FILE, DB_FILE, key)
    # إذا لم يكن هناك ملف مشفر، سيتم إنشاء قاعدة بيانات جديدة تلقائياً عند أول استخدام
    return key

# تهيئة قاعدة البيانات وإنشاء الجداول

def initialize_database():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS user_pin (
                id INTEGER PRIMARY KEY,
                pin_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                app_name TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                category TEXT NOT NULL,
                UNIQUE(username, app_name)
            );
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                language TEXT DEFAULT 'en',
                theme TEXT DEFAULT 'light'
            );
            CREATE TABLE IF NOT EXISTS encryption_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                master_key BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_pins (
                username TEXT PRIMARY KEY,
                pin_hash TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                last_attempt_time TIMESTAMP
            );
        ''')
        cursor.execute("SELECT COUNT(*) FROM user_pin WHERE id = 1")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO user_pin (id, pin_hash) VALUES (1, '')")
        conn.commit()
        return conn, cursor
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Failed to initialize database: {str(e)}\nPlease make sure the database file is accessible.")
        sys.exit(1)

# إعادة تشفير قاعدة البيانات عند إغلاق التطبيق

def secure_database():
    key = get_or_create_db_key()
    if os.path.exists(DB_FILE):
        encrypt_file(DB_FILE, ENC_DB_FILE, key)
        os.remove(DB_FILE)
        print("user.db has been successfully encrypted and deleted.")

# مثال على كيفية الاستخدام:
if __name__ == "__main__":
    # عند بدء التطبيق
    key = prepare_database()
    conn, cursor = initialize_database()
    # ... هنا تضع منطق التطبيق الرئيسي ...
    # عند إغلاق التطبيق (مثلاً عند الخروج من البرنامج)
    conn.close()
    secure_database()
