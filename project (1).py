import csv
import re
import bcrypt
import requests
import sys

# File to store user credentials
CSV_FILE = 'regno.csv'
API_KEY = 'your_newsapi_key_here'  # Replace with your actual NewsAPI key

# Helper function to read the CSV and return user data
def read_users():
    users = {}
    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                users[row['email']] = {
                    'password': row['password'],
                    'security_question': row['security_question'],
                    'security_answer': row['security_answer']
                }
    except FileNotFoundError:
        pass  # File not found, no users exist yet
    return users

# Helper function to write user data to the CSV
def write_user(email, hashed_password, security_question, security_answer):
    with open(CSV_FILE, mode='a', newline='') as file:
        fieldnames = ['email', 'password', 'security_question', 'security_answer']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writerow({
            'email': email,
            'password': hashed_password.decode(),
            'security_question': security_question,
            'security_answer': security_answer
        })

# Function to validate email format
def is_valid_email(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email)

# Function to validate password complexity
def is_valid_password(password):
    return len(password) >= 8 and any(char in "!@#$%^&*()_+" for char in password)

# Function to hash the password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Function to verify hashed password
def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Function to prompt user to register
def register(users):
    print("\n--- User Registration ---")
    email = input("Enter email: ")

    # Check if email is already registered
    if email in users:
        print("Email is already registered. Please login or reset your password.")
        return

    # Validate email format
    if not is_valid_email(email):
        print("Invalid email format.")
        return

    # Get and validate password
    password = input("Enter password (min 8 chars, 1 special char): ")
    if not is_valid_password(password):
        print("Password does not meet complexity requirements.")
        return

    # Hash the password
    hashed_password = hash_password(password)

    # Security question for password recovery
    security_question = input("Enter a security question (for password recovery): ")
    security_answer = input("Enter the answer to your security question: ")

    # Store user data in the CSV file
    write_user(email, hashed_password, security_question, security_answer)
    print("Registration successful! You can now log in.")

# Function to prompt user to login
def login(users):
    attempts = 0
    while attempts < 5:
        email = input("Enter email: ")
        if not is_valid_email(email):
            print("Invalid email format.")
            continue

        password = input("Enter password: ")
        if email in users and check_password(users[email]['password'], password):
            print("Login successful!")
            return email  # Return email of the logged-in user
        else:
            print("Invalid email or password. Try again.")
            attempts += 1

        if attempts >= 5:
            print("Too many failed attempts. Please try again later.")
            sys.exit()

# Function to handle forgot password
def forgot_password(users):
    email = input("Enter your registered email: ")
    if email not in users:
        print("Email not found.")
        return

    security_question = users[email]['security_question']
    print(f"Security Question: {security_question}")
    answer = input("Enter your answer: ")

    if answer.lower() == users[email]['security_answer'].lower():
        new_password = input("Enter new password (min 8 chars, 1 special char): ")
        if is_valid_password(new_password):
            hashed_password = hash_password(new_password)
            users[email]['password'] = hashed_password.decode()
            print("Password reset successful!")
            update_user_data(users)
        else:
            print("Password does not meet complexity requirements.")
    else:
        print("Security answer is incorrect.")

# Function to update user data in CSV after password reset
def update_user_data(users):
    with open(CSV_FILE, mode='w', newline='') as file:
        fieldnames = ['email', 'password', 'security_question', 'security_answer']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for email, data in users.items():
            writer.writerow({
                'email': email,
                'password': data['password'],
                'security_question': data['security_question'],
                'security_answer': data['security_answer']
            })

# Function to fetch news from NewsAPI
def fetch_news(keyword):
    url = f'https://newsapi.org/v2/everything?q={keyword}&apiKey={API_KEY}&pageSize=5'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            articles = response.json().get('articles', [])
            if articles:
                print(f"\nTop 5 News for '{keyword}':")
                for i, article in enumerate(articles):
                    print(f"{i+1}. {article['title']} - Source: {article['source']['name']}")
            else:
                print(f"No news articles found for '{keyword}'.")
        else:
            print("Failed to fetch news. Please check your API key.")
    except requests.exceptions.RequestException:
        print("Network error. Please check your internet connection.")

# Main function to run the program
def main():
    users = read_users()

    # Prompt user to register, log in or reset password
    while True:
        choice = input("\n1. Register\n2. Login\n3. Forgot Password\nChoose an option: ")
        if choice == '1':
            register(users)
        elif choice == '2':
            email = login(users)
            break
        elif choice == '3':
            forgot_password(users)
        else:
            print("Invalid option. Please try again.")

    # Once logged in, prompt for news search keyword
    while True:
        keyword = input("\nEnter a keyword to search news (or 'exit' to quit): ")
        if keyword.lower() == 'exit':
            break
        fetch_news(keyword)

if __name__ == '__main__':
    main()
