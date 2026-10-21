from flask import Flask, request, session, redirect, url_for, flash, send_from_directory
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

# --- SERVICE WORKER ROUTE FOR PWA ---
@app.route('/service-worker.js')
def service_worker():
    return send_from_directory(app.static_folder, 'service-worker.js')

# --- SESSION TIMEOUT CHECK ---
@app.before_request
def check_session_timeout():
    allowed_routes = ['auth.login', 'auth.register', 'static', 'auth.setup_2fa', 'auth.verify_2fa', 'service_worker']
    
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