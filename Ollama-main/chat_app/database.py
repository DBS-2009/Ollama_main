import sqlite3
import bcrypt
import os
import sys

# Set database path relative to this file's directory
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chat_users.db")
print(f"Database path: {DATABASE_PATH}", file=sys.stderr)

def init_database():
    """Initialize the database and create all tables if they don't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    """)
    
    # Conversations table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    # Messages table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            role TEXT NOT NULL, -- 'user' or 'assistant'
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
        )
    """)
    
    # User preferences table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            theme TEXT DEFAULT 'dark',
            sound_enabled BOOLEAN DEFAULT 1,
            auto_save BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    # Run migrations to add missing columns to existing tables
    run_migrations(cursor)
    
    conn.commit()
    conn.close()

def run_migrations(cursor):
    """Run database migrations to add missing columns."""
    try:
        # Check if login_attempts column exists, if not add it
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'login_attempts' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0")
            print("Added login_attempts column to users table", file=sys.stderr)
        
        if 'locked_until' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP")
            print("Added locked_until column to users table", file=sys.stderr)
            
        if 'last_login' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
            print("Added last_login column to users table", file=sys.stderr)
            
    except Exception as e:
        print(f"Migration error: {e}", file=sys.stderr)

def hash_password(password):
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, password_hash):
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def user_exists(email):
    """Check if a user with the given email exists."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    
    return result is not None

def register_user(email, password):
    """
    Register a new user with email and password.
    Returns: (success, message)
    """
    print(f"[DB] Attempting to register: {email}", file=sys.stderr)
    
    if user_exists(email):
        msg = "Email already registered"
        print(f"[DB] {msg}", file=sys.stderr)
        return False, msg
    
    if len(password) < 6:
        msg = "Password must be at least 6 characters"
        print(f"[DB] {msg}", file=sys.stderr)
        return False, msg
    
    try:
        password_hash = hash_password(password)
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        print(f"[DB] Inserting user: {email}", file=sys.stderr)
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, password_hash)
        )
        
        conn.commit()
        conn.close()
        print(f"[DB] ✓ User registered successfully: {email}", file=sys.stderr)
        return True, "User registered successfully"
    except Exception as e:
        msg = f"Registration failed: {str(e)}"
        print(f"[DB] ✗ {msg}", file=sys.stderr)
        return False, msg

def authenticate_user(email, password):
    """
    Authenticate a user with email and password.
    Returns: (success, message)
    """
    print(f"[DB] Attempting to authenticate: {email}", file=sys.stderr)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    
    if result is None:
        print(f"[DB] User not found: {email}", file=sys.stderr)
        return False, "Invalid email or password"
    
    password_hash = result[0]
    if verify_password(password, password_hash):
        print(f"[DB] ✓ Authentication successful: {email}", file=sys.stderr)
        return True, "Authentication successful"
    else:
        print(f"[DB] ✗ Password mismatch for: {email}", file=sys.stderr)
        return False, "Invalid email or password"

def get_user(email):
    """Get user information by email."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, email, created_at FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {"id": result[0], "email": result[1], "created_at": result[2]}
    return None

def delete_user(email):
    """Delete a user by email."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM users WHERE email = ?", (email,))
    conn.commit()
    conn.close()

def get_all_users():
    """Get all users (for testing/admin purposes only)."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, email, created_at FROM users")
    results = cursor.fetchall()
    conn.close()
    
    return [{"id": row[0], "email": row[1], "created_at": row[2]} for row in results]

# -----------------------------
# Chat History Functions
# -----------------------------

def create_conversation(user_id, title=None):
    """Create a new conversation for a user."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO conversations (user_id, title) VALUES (?, ?)",
        (user_id, title or "New Conversation")
    )
    
    conversation_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return conversation_id

def save_message(conversation_id, role, content):
    """Save a message to a conversation."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)",
        (conversation_id, role, content)
    )
    
    message_id = cursor.lastrowid
    
    # Update conversation timestamp
    cursor.execute(
        "UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (conversation_id,)
    )
    
    conn.commit()
    conn.close()
    
    return message_id

def get_conversations(user_id, limit=50):
    """Get all conversations for a user."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT c.id, c.title, c.created_at, c.updated_at,
               COUNT(m.id) as message_count
        FROM conversations c
        LEFT JOIN messages m ON c.id = m.conversation_id
        WHERE c.user_id = ?
        GROUP BY c.id
        HAVING COUNT(m.id) > 0
        ORDER BY c.updated_at DESC
        LIMIT ?
    """, (user_id, limit))
    
    results = cursor.fetchall()
    conn.close()
    
    return [{
        "id": row[0],
        "title": row[1],
        "created_at": row[2],
        "updated_at": row[3],
        "message_count": row[4]
    } for row in results]

def get_conversation_messages(conversation_id):
    """Get all messages for a conversation."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, role, content, created_at
        FROM messages
        WHERE conversation_id = ?
        ORDER BY created_at ASC
    """, (conversation_id,))
    
    results = cursor.fetchall()
    conn.close()
    
    return [{
        "id": row[0],
        "role": row[1],
        "content": row[2],
        "created_at": row[3]
    } for row in results]

def update_conversation_title(conversation_id, title):
    """Update conversation title."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE conversations SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (title, conversation_id)
    )
    
    conn.commit()
    conn.close()

def delete_conversation(conversation_id):
    """Delete a conversation and all its messages."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
    cursor.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
    
    conn.commit()
    conn.close()

# -----------------------------
# User Management Functions
# -----------------------------

def update_last_login(user_id):
    """Update user's last login timestamp."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP, login_attempts = 0 WHERE id = ?",
        (user_id,)
    )
    
    conn.commit()
    conn.close()

def increment_login_attempts(email):
    """Increment failed login attempts for a user."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET login_attempts = login_attempts + 1 WHERE email = ?",
        (email,)
    )
    
    conn.commit()
    conn.close()

def reset_login_attempts(email):
    """Reset login attempts for a user."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET login_attempts = 0 WHERE email = ?",
        (email,)
    )
    
    conn.commit()
    conn.close()

def lock_account(email, minutes=30):
    """Lock user account for specified minutes."""
    from datetime import datetime, timedelta
    
    lock_until = datetime.now() + timedelta(minutes=minutes)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET locked_until = ? WHERE email = ?",
        (lock_until.isoformat(), email)
    )
    
    conn.commit()
    conn.close()

def is_account_locked(email):
    """Check if user account is locked."""
    from datetime import datetime
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT locked_until FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0]:
        locked_until = datetime.fromisoformat(result[0])
        return datetime.now() < locked_until
    
    return False

def get_user_by_id(user_id):
    """Get user information by ID."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, email, created_at, last_login, login_attempts, locked_until
        FROM users WHERE id = ?
    """, (user_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "id": result[0],
            "email": result[1],
            "created_at": result[2],
            "last_login": result[3],
            "login_attempts": result[4],
            "locked_until": result[5]
        }
    return None

# -----------------------------
# User Preferences Functions
# -----------------------------

def get_user_preferences(user_id):
    """Get user preferences."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT theme, sound_enabled, auto_save
        FROM user_preferences WHERE user_id = ?
    """, (user_id,))
    
    result = cursor.fetchone()
    
    if not result:
        # Create default preferences
        cursor.execute("""
            INSERT INTO user_preferences (user_id, theme, sound_enabled, auto_save)
            VALUES (?, 'dark', 1, 1)
        """, (user_id,))
        conn.commit()
        result = ('dark', 1, 1)
    
    conn.close()
    
    return {
        "theme": result[0],
        "sound_enabled": bool(result[1]),
        "auto_save": bool(result[2])
    }

def update_user_preferences(user_id, preferences):
    """Update user preferences."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE user_preferences 
        SET theme = ?, sound_enabled = ?, auto_save = ?, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
    """, (
        preferences.get('theme', 'dark'),
        int(preferences.get('sound_enabled', True)),
        int(preferences.get('auto_save', True)),
        user_id
    ))
    
    conn.commit()
    conn.close()

# -----------------------------
# Utility Functions
# -----------------------------

def get_user_stats(user_id):
    """Get user statistics."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get conversation count
    cursor.execute("SELECT COUNT(*) FROM conversations WHERE user_id = ?", (user_id,))
    conversation_count = cursor.fetchone()[0]
    
    # Get message count
    cursor.execute("""
        SELECT COUNT(*) FROM messages m
        JOIN conversations c ON m.conversation_id = c.id
        WHERE c.user_id = ?
    """, (user_id,))
    message_count = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "conversations": conversation_count,
        "messages": message_count
    }
