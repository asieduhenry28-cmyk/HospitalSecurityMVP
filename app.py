from flask import Flask, request, session, redirect, url_for, flash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback_secret_key')

# --- IMPORT AND REGISTER BLUEPRINTS ---
from blueprints.auth import auth
from blueprints.main import main
from blueprints.admin import admin

app.register_blueprint(auth)
app.register_blueprint(main)
app.register_blueprint(admin)

# --- SESSION TIMEOUT CHECK ---
@app.before_request
def check_session_timeout():
    # Notice how the allowed routes now have the blueprint name prefix!
    allowed_routes = ['auth.login', 'auth.register', 'static', 'auth.setup_2fa', 'auth.verify_2fa']
    
    if request.endpoint in allowed_routes:
        return

    if 'user_id' in session:
        now = datetime.now()
        last_activity = session.get('last_activity')
        
        if last_activity:
            last_activity_time = datetime.fromisoformat(last_activity)
            if now - last_activity_time > timedelta(minutes=10):
                session.clear()
                flash("Session expired due to inactivity. Please log in again.", "error")
                return redirect(url_for('auth.login'))
        
        session['last_activity'] = now.isoformat()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
    
    