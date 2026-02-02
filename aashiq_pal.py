import streamlit as st
import requests
from bs4 import BeautifulSoup
import time
import schedule
import threading
import os
import sys
import hashlib
import logging

# Set page title and icon
st.set_page_config(page_title="AASHIQ PAL", page_icon="💖")

# Background image
st.markdown("""
<style>
body {
    background-image: url('https://example.com/background-image.jpg');
    background-size: cover;
}
</style>
""", unsafe_allow_html=True)

# Title
st.title("AASHIQ PAL 💖")

# Logger
logging.basicConfig(filename='log.log', level=logging.INFO)
logger = logging.getLogger(__name__)

# Admin Panel
admin_password = "admin123"  # default password
admin_password_hash = hashlib.sha256(admin_password.encode()).hexdigest()

def login_admin(password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash == admin_password_hash:
        return True
    return False

def admin_panel():
    st.subheader("Admin Panel")
    password = st.text_input("Enter Admin Password", type="password")
    if st.button("Login"):
        if login_admin(password):
            st.success("Logged in successfully!")
            # Admin panel content here
            st.write("Welcome to admin panel!")
        else:
            st.error("Invalid password")

# Facebook Login Credentials
username = st.text_input("Username")
password = st.text_input("Password", type="password")
target_id = st.text_input("Target ID")
message = st.text_input("Message")
interval = st.text_input("Interval (in seconds)")

# Login Function
def login_facebook(username, password):
    session = requests.Session()
    response = session.get("https://www.facebook.com")
    soup = BeautifulSoup(response.text, 'html.parser')
    # Extract CSRF Token
    csrf_token = soup.find('input', {'name': 'fb_dtsg'}).get('value')
    # Login Payload
    payload = {
        'email': username,
        'pass': password,
        'fb_dtsg': csrf_token
    }
    # Login Request
    response = session.post("https://www.facebook.com/login.php", data=payload)
    return session

# Send SMS Function
def send_message(session, target_id, message):
    # Send message code here
    logger.info(f"Message sent to {target_id}")
    return True

# Main Function
def main():
    st.sidebar.title("Menu")
    menu = st.sidebar.selectbox("Select Option", ["Home", "Admin Panel", "Automation Control 📡", "Live Logs"])
    if menu == "Home":
        if st.button("Login"):
            session = login_facebook(username, password)
            # Save cookies
            with open("cookies.txt", "w") as f:
                f.write(str(session.cookies.get_dict()))
            st.success("Logged in successfully!")

        # Send Message
        if st.button("Start Sending"):
            def send_message_loop():
                while True:
                    try:
                        session = requests.Session()
                        with open("cookies.txt", "r") as f:
                            cookies = eval(f.read())
                        session.cookies.update(cookies)
                        send_message(session, target_id, message)
                        time.sleep(int(interval))
                    except Exception as e:
                        logger.error(e)
                        time.sleep(60)  # 1 minute

            threading.Thread(target=send_message_loop, daemon=True).start()
            st.success("Message sending started successfully!")

        # Uptime
        def uptime():
            while True:
                try:
                    os.system("uptime")
                    time.sleep(60)  # 1 minute
                except Exception as e:
                    logger.error(e)
                    time.sleep(60)  # 1 minute

        threading.Thread(target=uptime, daemon=True).start()
    elif menu == "Admin Panel":
        admin_panel()
    elif menu == "Automation Control 📡":
        st.subheader("Automation Control")
        if st.button("Start Automation"):
            # Start automation code here
            logger.info("Automation started")
            st.success("Automation started successfully!")
        if st.button("Stop Automation"):
            # Stop automation code here
            logger.info("Automation stopped")
            st.success("Automation stopped successfully!")
    elif menu == "Live Logs":
        st.subheader("Live Logs")
        with open("log.log", "r") as f:
            logs = f.read()
        st.text(logs)

if __name__ == "__main__":
    main()