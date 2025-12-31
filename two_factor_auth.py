import bcrypt
import pyotp
import qrcode
import os
import json
import getpass

DB_FILE = "users.json"

# ------------------ Utilities ------------------

def load_users():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=4)

# ------------------ Registration ------------------

def register():
    users = load_users()
    username = input("Choose username: ")

    if username in users:
        print("User already exists.")
        return

    password = getpass.getpass("Choose password: ").encode()
    hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    users[username] = {
        "password": hashed_pw,
        "secret": secret
    }

    save_users(users)

    print("\nScan this QR code with Google Authenticator or similar app:")
    uri = totp.provisioning_uri(name=username, issuer_name="2FA Project")
    qr = qrcode.make(uri)
    qr.show()

    print("Registration successful.\n")

# ------------------ Login ------------------

def login():
    users = load_users()
    username = input("Username: ")

    if username not in users:
        print("User not found.")
        return

    password = getpass.getpass("Password: ").encode()
    stored_hash = users[username]["password"].encode()

    if not bcrypt.checkpw(password, stored_hash):
        print("Incorrect password.")
        return

    otp_input = input("Enter OTP from Authenticator app: ")
    totp = pyotp.TOTP(users[username]["secret"])

    if totp.verify(otp_input):
        print("\n✅ Login successful! 2FA verified.")
    else:
        print("\n❌ Invalid OTP. Access denied.")

# ------------------ Main Menu ------------------

def main():
    while True:
        print("\n--- Two-Factor Authentication System ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select option: ")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
