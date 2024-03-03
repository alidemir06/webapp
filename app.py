import streamlit as st
import sqlite3
import pandas as pd 
import bcrypt
import re
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from github import Github

def get_github_project_links(username, token=None):
    if token:
        g = Github(token)
    else:
        g = Github()  # If you're using this script for personal use, you might not need a token

    user = g.get_user(username)
    repos = user.get_repos()

    project_links = [repo.html_url for repo in repos]

    return project_links

def show_github_projects(links):
    for link in links:
        label = link.split("/")[-1]
        st.link_button(label=label, url=link)

def delete_user(conn, username):
    """
    Delete the user's account from the database based on their username.
    
    Parameters:
        conn (sqlite3.Connection): SQLite database connection.
        username (str): Username of the user whose account is to be deleted.
    
    Returns:
        bool: True if the account is deleted successfully, False otherwise.
    """
    sql_delete_user = """
        DELETE FROM userstable
        WHERE username = ?
    """
    try:
        c = conn.cursor()
        c.execute(sql_delete_user, (username,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(e)
        return False

def get_user_email(conn, username):
    sql_select_email = """
        SELECT email FROM userstable WHERE username = ?
    """
    try:
        c = conn.cursor()
        c.execute(sql_select_email, (username,))
        email = c.fetchone()
        if email:
            return email[0]  # Return the email from the tuple
        else:
            return None
    except sqlite3.Error as e:
        print(e)
        return None

def send_email(conn, username, key):
    
    try:
        # Email configuration
        sender_email = 'alidmr1294@gmail.com'
        receiver_email = get_user_email(conn, username)
        password = 'dylh ncax wsnf lvqt'

        # Create a multipart message and set headers
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receiver_email
        message['Subject'] = 'Test Email from Python'

        # Add body to email
        body = key
        message.attach(MIMEText(body, 'plain'))

        # Connect to SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
        
            server.starttls()  # Secure the connection
            server.login(user=sender_email, password=password)
            text = message.as_string()
            server.sendmail(from_addr=sender_email, to_addrs=receiver_email, msg=text)
            print('Email sent successfully!')
    except Exception as e:
        print(f"error: {e}")
    

# DB Management
def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except sqlite3.Error as e:
        print(e)
    return conn

def create_usertable(conn):
    sql_create_table = """
        CREATE TABLE IF NOT EXISTS userstable (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        );
    """
    try:
        c = conn.cursor()
        c.execute(sql_create_table)
    except sqlite3.Error as e:
        print(e)

def add_userdata(conn, username, password, email):
    sql_insert_user = """
        INSERT INTO userstable (username, password, email)
        VALUES (?, ?, ?)
    """
    try:
        c = conn.cursor()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute(sql_insert_user, (username, hashed_password, email))
        conn.commit()
    except sqlite3.Error as e:
        print(e)

def login_user(conn, username, password):
    sql_select_user = """
        SELECT id, password FROM userstable WHERE username = ?
    """
    try:
        c = conn.cursor()
        c.execute(sql_select_user, (username,))
        user = c.fetchone()
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                return user[0]
    except sqlite3.Error as e:
        print(e)
    return None




# Function to validate password against requirements
def is_valid_password(password):
    # Password length should be at least 8 characters
    if len(password) < 8:
        return False
    # Password should contain at least one uppercase letter
    if not re.search("[A-Z]", password):
        return False
    # Password should contain at least one lowercase letter
    if not re.search("[a-z]", password):
        return False
    # Password should contain at least one digit
    if not re.search("[0-9]", password):
        return False
    # Password should contain at least one special character
    if not re.search("[!@#$%^&*()-_=+{};:,<.>]", password):
        return False
    return True

# Function to validate email
def is_valid_email(email):
    # Regular expression for validating email addresses
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email)

# Function to generate a random temporary password
def generate_temp_password():
    temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    return temp_password

# Function to update user's password in the database
def update_password(conn, username, new_password):
    sql_update_password = """
        UPDATE userstable
        SET password = ?
        WHERE username = ?
    """
    try:
        c = conn.cursor()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute(sql_update_password, (hashed_password, username))
        conn.commit()
    except sqlite3.Error as e:
        print(e)

def main():
    """Simple Login App"""

    conn = create_connection("data.db")

    create_usertable(conn)  # Create the user table if it doesn't exist

    st.title("Simple Login App")

    menu = ["Home", "Login", "SignUp"]

    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.subheader("Home")

    elif choice == "Login":
        st.subheader("Login Section")

        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        login_checkbox = st.sidebar.checkbox("Login")
        forgot_password_checkbox = st.sidebar.checkbox("Forgot Password")
        if login_checkbox:
            if not username or not password:
                st.warning("Please enter both username and password.")
            else:
                user_id = login_user(conn, username, password)
                if user_id:
                    st.sidebar.success("Logged in as {}".format(username))
                    task = st.selectbox("Task", ["Add Post", "Analytics", "Profiles", "Delete Account", "Change Password", "Github"])
                    if task == "Add Post":
                        st.subheader("Add your post")
                    
                    elif task == "Delete Account":
                        if st.button("Delete Account"):
                             delete_user(conn, username)
                             st.success("Your account has been successfully deleted.")
                    elif task == "Change Password":
                        st.subheader("Change Password")
                        current_password = st.text_input("Current Password", type="password")
                        new_password = st.text_input("New Password", type="password")
                        confirm_new_password = st.text_input("Confirm New Password", type="password")
                        
                        if st.button("Change Password"):
                            if not current_password or not new_password or not confirm_new_password:
                                st.warning("Please fill in all fields.")
                            elif new_password != confirm_new_password:
                                st.warning("New passwords do not match.")
                            elif not is_valid_password(new_password):
                                st.warning("New password does not meet requirements.")
                                st.info("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")  
                            else:
                                # Check if the current password is correct
                                user_id = login_user(conn, username, current_password)
                                if user_id:
                                    # Update the password in the database
                                    update_password(conn, username, new_password)
                                    st.success("Password changed successfully.")
                                else:
                                    st.warning("Incorrect password. Please try again.")

                    elif task == "Github":
                        github_username = st.text_input("Enter your Github username")
                        if st.button("Fetch GitHub Repositories"):
                            links = get_github_project_links(github_username)
                            show_github_projects(links)

                    elif task == "Analytics":
                        st.subheader("Analytics")
                    elif task == "Profiles":
                        st.subheader("Profiles")
                        # Fetching all users' data is not recommended in production, 
                        # but for this example, let's fetch it
                        c = conn.cursor()
                        c.execute("SELECT username FROM userstable")
                        user_data = c.fetchall()
                        user_df = pd.DataFrame(user_data, columns=["Username"])
                        st.dataframe(user_df)
                else:
                    st.warning("Incorrect username/password")
        elif forgot_password_checkbox:
            st.subheader("Forgot Password")
            forgot_username = st.text_input("Username",key="12345")
            if forgot_username:
                # Check if the username exists
                c = conn.cursor()
                c.execute("SELECT * FROM userstable WHERE username=?", (forgot_username,))
                existing_user = c.fetchone()
                if not existing_user:
                    st.error("Username does not exist.")
                else:
                    # Generate a temporary password
                    temp_password = generate_temp_password()
                    send_email(conn, username = forgot_username, key = temp_password)
                    # Update the user's password in the database
                    update_password(conn, forgot_username, temp_password)
                    st.success(f"A temporary password has been sent to your email associated with {forgot_username}. Please check your email and login using the temporary password.")

    elif choice == "SignUp":
        st.subheader("Create New Account")

        # Create a form for signup
        with st.form(key='signup_form', clear_on_submit=True):
            new_user = st.text_input("Username")
            new_email = st.text_input("Email")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            submitted = st.form_submit_button("SignUp")

            if submitted:
                if not new_user or not new_email or not new_password or not confirm_password:
                    st.warning("Please fill in all fields.")
                elif not is_valid_email(new_email):
                    st.warning("Invalid email address.")
                elif new_password != confirm_password:
                    st.warning("Passwords do not match.")
                elif not is_valid_password(new_password):
                    st.warning("Password does not meet requirements.")
                    st.info("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
                else:
                    # Check if the username already exists
                    c = conn.cursor()
                    c.execute("SELECT * FROM userstable WHERE username=?", (new_user,))
                    existing_user = c.fetchone()
                    if existing_user:
                        st.warning("Username already exists. Please choose a different username.")
                    else:
                        # Process signup
                        add_userdata(conn, username=new_user, password=new_password, email=new_email)
                        st.success("You have created a valid account...")
                        st.info("Go to the login menu to login")


    conn.close()

if __name__ == "__main__":
    main()
