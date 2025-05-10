import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# 🔐 Fixed Fernet Key
KEY = b'W3aCgbUqHtO9yR9Q1CFY3zDWSzGomXlD4nYYFGJY3Jg='  # Replace with your secure key
cipher = Fernet(KEY)

# 🌐 Session State Initialization
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # Format: {encrypted_text: {"passkey": hashed_passkey}}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# 🔒 Hash Function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# 🔐 Encrypt Data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# 🔓 Decrypt Data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    data = st.session_state.stored_data.get(encrypted_text)

    if data and data["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# 🌐 UI
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# 🏠 Home Page
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("This system allows you to **securely store and retrieve** your data using a passkey.")

# 💾 Store Data
elif choice == "Store Data":
    st.subheader("💾 Store Your Data Securely")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "passkey": hash_passkey(passkey)
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.text_area("🔐 Save This Encrypted Text to Retrieve Later:", value=encrypted_text, height=100)
        else:
            st.error("⚠️ Please enter both data and passkey.")

# 🔍 Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Access Denied. Go to the 'Login' tab to reauthorize.")
    else:
        st.subheader("🔍 Retrieve Your Encrypted Data")
        encrypted_input = st.text_area("Paste your encrypted text:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_input and passkey:
                decrypted = decrypt_data(encrypted_input, passkey)
                if decrypted:
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Data:", value=decrypted, height=100)
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts remaining: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.authorized = False
                        st.warning("🔐 Too many failed attempts. Please log in again via the 'Login' tab.")
            else:
                st.error("⚠️ Please provide both the encrypted text and passkey.")

# 🔑 Admin Reauthorization
elif choice == "Login":
    st.subheader("🔑 Admin Reauthorization")
    login_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if login_pass == "zs833251":  # Replace with secure admin password
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized. You can now retrieve data.")
        else:
            st.error("❌ Incorrect admin password.")


