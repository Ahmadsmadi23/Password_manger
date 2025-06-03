##############  Secure Vault - Password Manager ##############

Secure Vault is a secure, offline password manager application built using Python. It provides a graphical interface for managing and encrypting your application credentials with advanced cryptographic methods.

 Passwords are encrypted using AES encryption (via the cryptography library), and the master password is hashed to ensure maximum protection. All data is stored locally in a secure SQLite database.


##############  Project Idea    ##############

The goal is to help users securely store, organize, and access their passwords without depending on internet connectivity, ensuring full privacy and data control.

- The application supports  "Arabic and English " languages.  
- The user interface is  "interactive and easy to use ".  
- The project is  "scalable and open for future enhancements " (e.g., two-factor authentication, cloud sync).
 

##############   Tools & Technologies Used   ##############

-  "Python 3 "
-  "Tkinter + CustomTkinter " for the GUI
-  "SQLite " for local database storage
-  "Argon2 " for password hashing
-  "AES-256 + ECC " for data encryption
-  "SHA-256 " for PIN hashing

 

##############  Security Features   ##############

- Passwords are hashed using `Argon2` for secure storage
- Application passwords are encrypted with `AES-256` and ECC keys
- Automatic blocking after 5 failed login attempts
- Security question mechanism for password reset
- Completely offline with no internet dependency



############## Project Structure  ##############

  File   Description 
`login.py`   Login window and user authentication  
`Register.py`   New user registration with security question  
`resetpasswored.py`   Password reset via security question  
`Face2.py`   Main dashboard for managing passwords  
`user.db`   Local SQLite database for storing data  

 

##############   How to Run   ##############
On first launch, the user is prompted to create a master password.

The master password is hashed and saved in the database.

For every login, the user must enter the correct master password to unlock the vault.

Each saved password is encrypted using AES (Fernet).

When the user views a password, it is decrypted using the same key derived from the master password.

Install the required libraries:
pip install argon2-cffi cryptography customtkinter


Run the application:
python login.py


 

##############  Database    ##############

- The database file `user.db` is generated automatically.  
- All passwords are stored in  "encrypted form " using secure algorithms.  
- All data is stored  "locally ", with  "no internet connection or external server " involved.


##############   Developer  ##############
Ahmad Ali AL-Smadi
Abdallah Mahmoud Jawarneh
Furqan Haroon Megdady
Rou'a Odeh Abuzarour
