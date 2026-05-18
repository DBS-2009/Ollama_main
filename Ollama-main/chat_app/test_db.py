from database import init_database, register_user, authenticate_user, get_all_users
import os

# Check if DB exists
print(f"DB file exists before: {os.path.exists('chat_users.db')}")

# Initialize
init_database()
print("Database initialized")

# Try to register a test user
success, message = register_user("test@test.com", "password123")
print(f"Register result: {success}, {message}")

# Try to authenticate
auth_success, auth_message = authenticate_user("test@test.com", "password123")
print(f"Auth result: {auth_success}, {auth_message}")

# Get all users
users = get_all_users()
print(f"All users in DB: {users}")

print(f"DB file exists after: {os.path.exists('chat_users.db')}")
