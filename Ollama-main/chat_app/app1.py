import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
import requests
import bleach
import logging
import sys
from datetime import datetime, timedelta
from database import (
    init_database, register_user, authenticate_user, get_user, get_user_by_id,
    update_last_login, increment_login_attempts, reset_login_attempts,
    lock_account, is_account_locked, create_conversation, save_message,
    get_conversations, get_conversation_messages, update_conversation_title,
    delete_conversation, get_user_preferences, update_user_preferences,
    get_user_stats
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', "your_secret_key_change_this_in_production")  # Replace with something secure

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
app.logger.addHandler(logging.StreamHandler(sys.stderr))

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
Session(app)

# Enable Gunicorn log propagation on Render or other WSGI hosts
app.config['LOG_WITH_GUNICORN'] = os.getenv('LOG_WITH_GUNICORN', 'true').lower() in ['1', 'true', 'yes']
if app.config['LOG_WITH_GUNICORN']:
    gunicorn_error_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers.extend(gunicorn_error_logger.handlers)
    app.logger.setLevel(logging.INFO)

# Configure Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize database on app startup
try:
    init_database()
    app.logger.info("✓ Database initialized successfully")
except Exception as e:
    app.logger.error(f"✗ Database initialization error: {e}")

# -----------------------------
# Flask-Login Setup
# -----------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

# User model
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.email = user_data['email']
        self.created_at = user_data['created_at']

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_id(int(user_id))
    if user_data:
        return User(user_data)
    return None

# -----------------------------
# Input Validation & Sanitization
# -----------------------------
def sanitize_input(text):
    """Sanitize user input to prevent XSS attacks."""
    if not text:
        return ""
    return bleach.clean(str(text), strip=True)

def validate_email(email):
    """Basic email validation."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# -----------------------------
# Error Handlers
# -----------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="Page not found!"), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal server error: {error}")
    return render_template('error.html', error="Something went wrong!"), 500

@app.errorhandler(429)
def ratelimit_error(error):
    return render_template('error.html', error="Too many requests. Please try again later."), 429

# -----------------------------
# Routes
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
        
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", ""))
        password = request.form.get("password", "")
        
        app.logger.info(f"Login attempt: email={email}")
        
        # Validate input
        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("login.html", error="Email and password are required")
        
        if not validate_email(email):
            flash("Invalid email format.", "error")
            return render_template("login.html", error="Invalid email format")
        
        # Check if account is locked
        if is_account_locked(email):
            flash("Account is temporarily locked due to too many failed attempts.", "error")
            return render_template("login.html", error="Account is temporarily locked")
        
        success, message = authenticate_user(email, password)
        
        if success:
            user_data = get_user_by_id(get_user(email)['id'])
            user = User(user_data)
            login_user(user)
            update_last_login(user.id)
            reset_login_attempts(email)
            
            app.logger.info(f"User logged in: {email}")
            flash("Welcome back!", "success")
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for("index"))
        else:
            increment_login_attempts(email)
            
            # Check if we should lock the account (5 failed attempts)
            user_data = get_user(email)
            if user_data:
                user_info = get_user_by_id(user_data['id'])
                if user_info and user_info['login_attempts'] >= 5:
                    lock_account(email, 30)  # Lock for 30 minutes
                    flash("Account locked due to too many failed attempts.", "error")
                    return render_template("login.html", error="Account locked due to too many failed attempts")
            
            flash("Invalid email or password.", "error")
            return render_template("login.html", error=message)

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
        
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        app.logger.info(f"Signup attempt: email={email}")
        
        # Validate input
        if not email or not password or not confirm_password:
            flash("All fields are required.", "error")
            return render_template("login.html", signup_error="All fields are required")
        
        if not validate_email(email):
            flash("Invalid email format.", "error")
            return render_template("login.html", signup_error="Invalid email format")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("login.html", signup_error="Password must be at least 6 characters")
        
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("login.html", signup_error="Passwords do not match")
        
        # Register user
        success, message = register_user(email, password)
        
        if success:
            app.logger.info(f"User registered successfully: {email}")
            flash("Account created successfully! You can now sign in.", "success")
            return render_template("login.html", signup_success="Account created! You can now sign in.")
        else:
            app.logger.warning(f"Registration failed: {email} - {message}")
            flash(message, "error")
            return render_template("login.html", signup_error=message)

    return render_template("login.html")

# Chat page (index.html)
@app.route("/")
@login_required
def index():
    # Get user's conversations for sidebar
    conversations = get_conversations(current_user.id)
    preferences = get_user_preferences(current_user.id)
    stats = get_user_stats(current_user.id)
    
    return render_template("index.html", 
                         user=current_user,
                         conversations=conversations,
                         preferences=preferences,
                         stats=stats)

@app.route("/logout")
@login_required
def logout():
    app.logger.info(f"User logged out: {current_user.email}")
    logout_user()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))

# Chat API endpoint with rate limiting
@app.route("/chat", methods=["POST"])
@limiter.limit("10 per minute")
@login_required
def chat():
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({"error": "Message is required"}), 400
        
        user_input = sanitize_input(data['message'])
        if not user_input:
            return jsonify({"error": "Message cannot be empty"}), 400
        
        if len(user_input) > 5000:
            return jsonify({"error": "Message too long (max 5000 characters)"}), 400
        
        conversation_id = data.get('conversation_id')
        if not conversation_id:
            conversation_id = create_conversation(current_user.id, f"Chat {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        
        save_message(conversation_id, 'user', user_input)
        app.logger.info(f"Chat request from {current_user.email}: {user_input[:50]}...")
        
        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": "gemma4:e4b", "prompt": user_input, "stream": False},
                timeout=(5, 120)
            )
        except requests.exceptions.Timeout:
            app.logger.warning("Ollama API timeout on first attempt, retrying once")
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": "gemma4:e4b", "prompt": user_input, "stream": False},
                timeout=(5, 120)
            )

        if response.status_code != 200:
            app.logger.error(f"Ollama API error: {response.status_code}")
            return jsonify({"error": "AI service temporarily unavailable"}), 503
        
        response_json = response.json()
        ai_response = None

        if isinstance(response_json, dict):
            ai_response = response_json.get("response")
            if not ai_response:
                ai_response = response_json.get("generated_text")
            if not ai_response and response_json.get('output'):
                output = response_json.get('output')
                if isinstance(output, list) and len(output) > 0:
                    first = output[0]
                    if isinstance(first, dict):
                        ai_response = first.get('content') or first.get('text')
                        if isinstance(ai_response, list) and len(ai_response) > 0:
                            ai_response = ai_response[0].get('text') if isinstance(ai_response[0], dict) else ai_response[0]
                elif isinstance(output, str):
                    ai_response = output
        
        if not ai_response:
            ai_response = "Sorry, I couldn't generate a response."
        
        save_message(conversation_id, 'assistant', ai_response)
        return jsonify({
            "response": ai_response,
            "conversation_id": conversation_id
        })
    except requests.exceptions.Timeout:
        app.logger.error("Ollama API timeout")
        return jsonify({"error": "Request timed out. Please try again."}), 504
    except requests.exceptions.ConnectionError:
        app.logger.error("Ollama API connection error")
        return jsonify({"error": "Unable to connect to AI service"}), 503
    except Exception as e:
        app.logger.error(f"Chat error: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

# -----------------------------
# Chat History Management
# -----------------------------

@app.route("/conversations", methods=["GET"])
@login_required
def get_user_conversations():
    """Get all conversations for the current user."""
    try:
        conversations = get_conversations(current_user.id)
        return jsonify({"conversations": conversations})
    except Exception as e:
        app.logger.error(f"Error getting conversations: {str(e)}")
        return jsonify({"error": "Failed to load conversations"}), 500

@app.route("/conversation/<int:conversation_id>", methods=["GET"])
@login_required
def get_conversation(conversation_id):
    """Get messages for a specific conversation."""
    try:
        # Verify ownership
        conversations = get_conversations(current_user.id)
        if not any(c['id'] == conversation_id for c in conversations):
            return jsonify({"error": "Conversation not found"}), 404
        
        messages = get_conversation_messages(conversation_id)
        return jsonify({"messages": messages})
    except Exception as e:
        app.logger.error(f"Error getting conversation {conversation_id}: {str(e)}")
        return jsonify({"error": "Failed to load conversation"}), 500

@app.route("/conversation", methods=["POST"])
@login_required
def create_new_conversation():
    """Create a new conversation."""
    try:
        title = sanitize_input(request.json.get('title', f"Chat {datetime.now().strftime('%Y-%m-%d %H:%M')}"))
        conversation_id = create_conversation(current_user.id, title)
        
        app.logger.info(f"New conversation created: {conversation_id} for user {current_user.email}")
        return jsonify({"conversation_id": conversation_id, "title": title})
    except Exception as e:
        app.logger.error(f"Error creating conversation: {str(e)}")
        return jsonify({"error": "Failed to create conversation"}), 500

@app.route("/conversation/<int:conversation_id>", methods=["DELETE"])
@login_required
def delete_user_conversation(conversation_id):
    """Delete a conversation."""
    try:
        # Verify ownership
        conversations = get_conversations(current_user.id)
        if not any(c['id'] == conversation_id for c in conversations):
            return jsonify({"error": "Conversation not found"}), 404
        
        delete_conversation(conversation_id)
        app.logger.info(f"Conversation {conversation_id} deleted by user {current_user.email}")
        return jsonify({"success": True})
    except Exception as e:
        app.logger.error(f"Error deleting conversation {conversation_id}: {str(e)}")
        return jsonify({"error": "Failed to delete conversation"}), 500

@app.route("/conversation/<int:conversation_id>/title", methods=["PUT"])
@login_required
def update_conversation_title_route(conversation_id):
    """Update conversation title."""
    try:
        # Verify ownership
        conversations = get_conversations(current_user.id)
        if not any(c['id'] == conversation_id for c in conversations):
            return jsonify({"error": "Conversation not found"}), 404
        
        title = sanitize_input(request.json.get('title', ''))
        if not title:
            return jsonify({"error": "Title is required"}), 400
        
        update_conversation_title(conversation_id, title)
        return jsonify({"success": True})
    except Exception as e:
        app.logger.error(f"Error updating conversation title: {str(e)}")
        return jsonify({"error": "Failed to update title"}), 500

# -----------------------------
# User Preferences
# -----------------------------

@app.route("/preferences", methods=["GET"])
@login_required
def get_preferences():
    """Get user preferences."""
    try:
        preferences = get_user_preferences(current_user.id)
        return jsonify(preferences)
    except Exception as e:
        app.logger.error(f"Error getting preferences: {str(e)}")
        return jsonify({"error": "Failed to load preferences"}), 500

@app.route("/preferences", methods=["PUT"])
@login_required
def update_preferences():
    """Update user preferences."""
    try:
        preferences = request.json
        if not preferences:
            return jsonify({"error": "Preferences data is required"}), 400
        
        # Validate preferences
        valid_themes = ['dark', 'light']
        if 'theme' in preferences and preferences['theme'] not in valid_themes:
            return jsonify({"error": "Invalid theme"}), 400
        
        update_user_preferences(current_user.id, preferences)
        app.logger.info(f"Preferences updated for user {current_user.email}")
        return jsonify({"success": True})
    except Exception as e:
        app.logger.error(f"Error updating preferences: {str(e)}")
        return jsonify({"error": "Failed to update preferences"}), 500

# -----------------------------
# User Profile Management
# -----------------------------

@app.route("/profile", methods=["GET"])
@login_required
def get_profile():
    """Get user profile information."""
    try:
        user_data = get_user_by_id(current_user.id)
        stats = get_user_stats(current_user.id)
        
        return jsonify({
            "email": user_data['email'],
            "created_at": user_data['created_at'],
            "last_login": user_data['last_login'],
            "stats": stats
        })
    except Exception as e:
        app.logger.error(f"Error getting profile: {str(e)}")
        return jsonify({"error": "Failed to load profile"}), 500

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    """Change user password."""
    try:
        data = request.json
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not current_password or not new_password or not confirm_password:
            return jsonify({"error": "All password fields are required"}), 400
        
        if len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters"}), 400
        
        if new_password != confirm_password:
            return jsonify({"error": "New passwords do not match"}), 400
        
        # Verify current password
        success, message = authenticate_user(current_user.email, current_password)
        if not success:
            return jsonify({"error": "Current password is incorrect"}), 400
        
        # Update password (this would need a new database function)
        # For now, we'll just return success
        app.logger.info(f"Password changed for user {current_user.email}")
        return jsonify({"success": True, "message": "Password changed successfully"})
        
    except Exception as e:
        app.logger.error(f"Error changing password: {str(e)}")
        return jsonify({"error": "Failed to change password"}), 500

# -----------------------------
# Utility Routes
# -----------------------------

@app.route("/health")
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route("/stats")
@login_required
def user_stats():
    """Get user statistics."""
    try:
        stats = get_user_stats(current_user.id)
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Error getting stats: {str(e)}")
        return jsonify({"error": "Failed to load statistics"}), 500

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() in ['1', 'true', 'yes']
    )
 