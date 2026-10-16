from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import mysql.connector
import pyotp
import subprocess
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback_secret_key')

# --- ENCRYPTION KEY ---
FERNET_KEY = os.getenv('FERNET_KEY').encode()
cipher_suite = Fernet(FERNET_KEY)

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME', 'hospital_security_mvp')
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

def log_action(user_id, action, details, ip_address):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (user_id, action, details, ip_address))
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"Failed to write to audit log: {err}")

# --- SESSION TIMEOUT CHECK ---
@app.before_request
def check_session_timeout():
    allowed_routes = ['login', 'register', 'static', 'setup_2fa', 'verify_2fa']
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
                return redirect(url_for('login'))
        
        session['last_activity'] = now.isoformat()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
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
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            if err.errno == 1062:
                flash("Username already exists.", "error")
                return render_template('register.html')
            else:
                flash(f"Database error: {err}", "error")
                return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
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
                return redirect(url_for('setup_2fa'))
            else:
                session['pre_2fa_user'] = {'id': user[0], 'username': user[2], 'secret': user[5]}
                cursor.close()
                conn.close()
                return redirect(url_for('verify_2fa'))
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

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

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
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid code. Please try again.", "error")
            return render_template('setup_2fa.html', secret=secret)

    new_secret = pyotp.random_base32()
    return render_template('setup_2fa.html', secret=new_secret)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

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
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid or expired code. Try again.", "error")
            return render_template('verify_2fa.html')

    return render_template('verify_2fa.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Fetch Dashboard Statistics
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM patients")
    total_patients = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM appointments")
    total_appointments = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'doctor' AND is_active = TRUE")
    total_doctors = cursor.fetchone()[0]
    
    cursor.close()
    conn.close()
    
    return render_template('dashboard.html', 
                           username=session['username'], 
                           role=session['role'],
                           total_patients=total_patients,
                           total_appointments=total_appointments,
                           total_doctors=total_doctors)

@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') not in ['admin', 'receptionist']:
        return "Access Denied: Only Admins and Receptionists can register patients.", 403

    if request.method == 'POST':
        full_name = request.form['full_name']
        dob = request.form['dob']
        gender = request.form['gender']
        contact = request.form['contact']

        encrypted_contact = cipher_suite.encrypt(contact.encode()).decode()

        conn = get_db_connection()
        cursor = conn.cursor()
        query = "INSERT INTO patients (full_name, date_of_birth, gender, contact_number) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (full_name, dob, gender, encrypted_contact))
        conn.commit()
        cursor.close()
        conn.close()

        log_action(session['user_id'], "PATIENT_ADDED", f"Registered new patient: {full_name}", request.remote_addr)
        flash(f"Patient '{full_name}' registered successfully!", "success")
        return redirect(url_for('view_patients'))

    return render_template('add_patient.html')

@app.route('/view_patients')
def view_patients():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT patient_id, full_name, date_of_birth, gender, contact_number, created_at FROM patients ORDER BY created_at DESC")
    raw_patients = cursor.fetchall()
    cursor.close()
    conn.close()
    
    patients = []
    for p in raw_patients:
        try:
            decrypted_contact = cipher_suite.decrypt(p[4].encode()).decode()
        except Exception:
            decrypted_contact = p[4]
        patients.append((p[0], p[1], p[2], p[3], decrypted_contact, p[5]))
    
    return render_template('view_patients.html', patients=patients)

@app.route('/schedule_appointment', methods=['GET', 'POST'])
def schedule_appointment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') not in ['admin', 'receptionist']:
        return "Access Denied: Only Admins and Receptionists can schedule appointments.", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        patient_id = request.form['patient_id']
        doctor_id = request.form['doctor_id']
        appointment_date = request.form['appointment_date']
        reason = request.form['reason']

        query = "INSERT INTO appointments (patient_id, doctor_id, appointment_date, reason) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (patient_id, doctor_id, appointment_date, reason))
        conn.commit()
        
        cursor.execute("SELECT full_name FROM patients WHERE patient_id = %s", (patient_id,))
        patient_name = cursor.fetchone()[0]
        
        log_action(session['user_id'], "APPOINTMENT_SCHEDULED", f"Scheduled appointment for {patient_name}", request.remote_addr)
        flash(f"Appointment scheduled successfully for {patient_name}!", "success")
        
        cursor.close()
        conn.close()
        return redirect(url_for('view_appointments'))

    cursor.execute("SELECT patient_id, full_name FROM patients ORDER BY full_name")
    patients = cursor.fetchall()
    
    cursor.execute("SELECT user_id, full_name FROM users WHERE role = 'doctor' ORDER BY full_name")
    doctors = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('schedule_appointment.html', patients=patients, doctors=doctors)

@app.route('/view_appointments')
def view_appointments():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    user_role = session.get('role')
    user_id = session['user_id']
    
    if user_role == 'doctor':
        query = """
            SELECT a.appointment_id, p.full_name AS patient_name, u.full_name AS doctor_name, 
                   a.appointment_date, a.reason, a.status
            FROM appointments a
            JOIN patients p ON a.patient_id = p.patient_id
            JOIN users u ON a.doctor_id = u.user_id
            WHERE a.doctor_id = %s
            ORDER BY a.appointment_date DESC
        """
        cursor.execute(query, (user_id,))
    else:
        query = """
            SELECT a.appointment_id, p.full_name AS patient_name, u.full_name AS doctor_name, 
                   a.appointment_date, a.reason, a.status
            FROM appointments a
            JOIN patients p ON a.patient_id = p.patient_id
            JOIN users u ON a.doctor_id = u.user_id
            ORDER BY a.appointment_date DESC
        """
        cursor.execute(query)
        
    appointments = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('view_appointments.html', appointments=appointments)

@app.route('/manage_users')
def manage_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied: Only Admins can manage users.", 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, full_name, username, role, is_active, created_at FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('manage_users.html', users=users)

@app.route('/toggle_user/<int:user_id>')
def toggle_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    if user_id == session['user_id']:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, is_active FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()
    
    if user:
        new_status = not user[1]
        cursor.execute("UPDATE users SET is_active = %s WHERE user_id = %s", (new_status, user_id))
        conn.commit()
        
        action = "USER_ACTIVATED" if new_status else "USER_DEACTIVATED"
        log_action(session['user_id'], action, f"{action} for user: {user[0]}", request.remote_addr)
        flash(f"User '{user[0]}' has been {'activated' if new_status else 'deactivated'}.", "success")
    
    cursor.close()
    conn.close()
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    if user_id == session['user_id']:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT full_name, username, role FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()
    
    if user:
        cursor.execute("""
            INSERT INTO deleted_users (original_user_id, full_name, username, role, deleted_by) 
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, user[0], user[1], user[2], session['user_id']))
        
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()
        
        log_action(session['user_id'], "USER_DELETED", f"Permanently deleted user: {user[1]}", request.remote_addr)
        flash(f"User '{user[1]}' has been permanently deleted and archived.", "success")
    
    cursor.close()
    conn.close()
    return redirect(url_for('manage_users'))

@app.route('/deleted_users')
def deleted_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT deleted_id, original_user_id, full_name, username, role, deleted_at, deleted_by FROM deleted_users ORDER BY deleted_at DESC")
    deleted = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('deleted_users.html', deleted=deleted)

@app.route('/audit_logs')
def audit_logs():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied: You must be an Admin to view this page.", 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT log_id, user_id, action, details, ip_address, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100")
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('audit_logs.html', logs=logs)

@app.route('/backup')
def backup_page():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied: Only Admins can access backups.", 403
    return render_template('backup.html')

@app.route('/download_backup')
def download_backup():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_filename = f"hospital_backup_{timestamp}.sql"
    backup_path = os.path.join(os.getcwd(), backup_filename)
    
    try:
        command = [
            "mysqldump",
            f"--host={db_config['host']}",
            f"--user={db_config['user']}",
            f"--password={db_config['password']}",
            db_config['database']
        ]
        
        with open(backup_path, "w") as f:
            subprocess.run(command, stdout=f, check=True)
            
        log_action(session['user_id'], "DATABASE_BACKUP", "Admin downloaded a database backup.", request.remote_addr)
        return send_file(backup_path, as_attachment=True)
        
    except Exception as e:
        flash(f"Backup Failed: {e}", "error")
        return redirect(url_for('backup_page'))

@app.route('/restore_backup', methods=['POST'])
def restore_backup():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    if 'backup_file' not in request.files:
        flash("No file uploaded.", "error")
        return redirect(url_for('backup_page'))
        
    file = request.files['backup_file']
    if file.filename == '':
        flash("No file selected.", "error")
        return redirect(url_for('backup_page'))
        
    if file and file.filename.endswith('.sql'):
        temp_path = os.path.join(os.getcwd(), "temp_restore.sql")
        file.save(temp_path)
        
        try:
            command = [
                "mysql",
                f"--host={db_config['host']}",
                f"--user={db_config['user']}",
                f"--password={db_config['password']}",
                db_config['database']
            ]
            
            with open(temp_path, "r") as f:
                subprocess.run(command, stdin=f, check=True)
                
            os.remove(temp_path)
            log_action(session['user_id'], "DATABASE_RESTORE", "Admin restored the database from a backup file.", request.remote_addr)
            flash("Database restored successfully!", "success")
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            flash(f"Restore Failed: {e}", "error")
            return redirect(url_for('backup_page'))
    else:
        flash("Invalid file format. Please upload a .sql file.", "error")
        return redirect(url_for('backup_page'))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], "LOGOUT", "User logged out.", request.remote_addr)
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)