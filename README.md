Secure Vault
Secure Vault is a standalone offline password manager built for Windows using Python and Tkinter. It allows users to store and manage their credentials securely, without any internet connection.

Passwords are encrypted using AES encryption (via the cryptography library), and the master password is hashed to ensure maximum protection. All data is stored locally in a secure SQLite database.

###################   Features   #################
Works completely offline

AES encryption for all saved passwords

Master password is stored as a secure hash

User-friendly interface using Tkinter (Windows only)

Data is saved locally using SQLite

Add, edit, and delete entries

Strong password generator included

################## How It Works  ##################
On first launch, the user is prompted to create a master password.

The master password is hashed and saved in the database.

For every login, the user must enter the correct master password to unlock the vault.

Each saved password is encrypted using AES (Fernet).

When the user views a password, it is decrypted using the same key derived from the master password.

Technologies Used
Language: Python 3

GUI: Tkinter

Encryption: cryptography (Fernet - AES-based)

Database: SQLite

##################   File Structure
main.py: Main application launcher

encryption.py: Encryption and hashing functions

database.py: SQLite functions (create, read, write)

ui/: Tkinter interface files

passwords.db: Local encrypted database

README.md: Project description

