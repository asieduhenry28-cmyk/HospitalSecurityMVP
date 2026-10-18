from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from datetime import datetime, timedelta
from extensions import get_db_connection, log_action

# Create the blueprint
auth = Blueprint('auth', __name__)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            query = "INSERT INTO users (full_name, username, password_hash, role) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (full_name, username, hashed_password, role))
            conn.commit()
            cursor.close()
            conn.close()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('auth.login'))
        except Exception as err:
            if "Duplicate entry" in str(err):
                flash("Username already exists.", "error")
            else:
                flash(f"Database error: {err}", "error")
            return render_template('register.html')

    return render_template('register.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_ip = request.remote_addr

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, full_name, username, password_hash, role, totp_secret, is_active, failed_attempts, lockout_until 
            FROM users WHERE username = %s
        """, (username,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            log_action(None, "LOGIN_FAILED", f"Failed login attempt for non-existent username: {username}", user_ip)
            flash("Invalid username or password.", "error")
            return render_template('login.html')

        if user[8] and user[8] > datetime.now():
            time_left = (user[8] - datetime.now()).seconds // 60
            cursor.close()
            conn.close()
            log_action(user[0], "LOGIN_FAILED", f"Attempted login to locked account: {username}", user_ip)
            flash(f"Account is locked due to multiple failed attempts. Try again in {time_left} minutes.", "error")
            return render_template('login.html')

        if check_password_hash(user[3], password):
            cursor.execute("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE user_id = %s", (user[0],))
            conn.commit()
            
            if not user[6]: 
                log_action(user[0], "LOGIN_FAILED", f"Deactivated account attempted login: {username}", user_ip)
                cursor.close()
                conn.close()
                flash("Your account has been deactivated. Please contact an Administrator.", "error")
                return render_template('login.html')
            
            log_action(user[0], "LOGIN_PASSWORD_SUCCESS", f"User {username} entered correct password.", user_ip)
            
            if user[5] is None: 
                session['pre_2fa_user'] = {'id': user[0], 'username': user[2]}
                cursor.close()
                conn.close()
                return redirect(url_for('auth.setup_2fa'))
            else:
                session['pre_2fa_user'] = {'id': user[0], 'username': user[2], 'secret': user[5]}
                cursor.close()
                conn.close()
                return redirect(url_for('auth.verify_2fa'))
        else:
            failed_attempts = user[7] + 1
            lockout_until = None
            
            if failed_attempts >= 3:
                lockout_until = datetime.now() + timedelta(minutes=15)
                log_action(user[0], "ACCOUNT_LOCKED", f"Account locked for 15 minutes due to 3 failed attempts.", user_ip)
                flash("Account locked for 15 minutes due to 3 failed attempts.", "error")
            else:
                flash(f"Invalid password. You have {3 - failed_attempts} attempts remaining.", "error")
                log_action(user[0], "LOGIN_FAILED", f"Failed login attempt {failed_attempts}/3 for username: {username}", user_ip)

            cursor.execute("UPDATE users SET failed_attempts = %s, lockout_until = %s WHERE user_id = %s", 
                           (failed_attempts, lockout_until, user[0]))
            conn.commit()
            cursor.close()
            conn.close()
            return render_template('login.html')

    return render_template('login.html')

@auth.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        secret = request.form['secret']
        code = request.form['code']
        
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            user_id = session['pre_2fa_user']['id']
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET totp_secret = %s WHERE user_id = %s", (secret, user_id))
            conn.commit()
            cursor.close()
            conn.close()
            
            log_action(user_id, "2FA_SETUP_COMPLETE", "User successfully set up 2FA.", request.remote_addr)
            
            session['user_id'] = user_id
            session['username'] = session['pre_2fa_user']['username']
            session['last_activity'] = datetime.now().isoformat()
            session.pop('pre_2fa_user', None)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE user_id = %s", (user_id,))
            role = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            session['role'] = role
            
            flash("2FA setup complete! Welcome to your dashboard.", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid code. Please try again.", "error")
            return render_template('setup_2fa.html', secret=secret)

    new_secret = pyotp.random_base32()
    return render_template('setup_2fa.html', secret=new_secret)

@auth.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form['code']
        secret = session['pre_2fa_user']['secret']
        
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            user_id = session['pre_2fa_user']['id']
            
            log_action(user_id, "LOGIN_SUCCESS_2FA", "User successfully logged in with 2FA.", request.remote_addr)
            
            session['user_id'] = user_id
            session['username'] = session['pre_2fa_user']['username']
            session['last_activity'] = datetime.now().isoformat()
            session.pop('pre_2fa_user', None)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE user_id = %s", (user_id,))
            role = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            session['role'] = role
            
            flash("Login successful!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid or expired code. Try again.", "error")
            return render_template('verify_2fa.html')

    return render_template('verify_2fa.html')

@auth.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], "LOGOUT", "User logged out.", request.remote_addr)
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('auth.login'))