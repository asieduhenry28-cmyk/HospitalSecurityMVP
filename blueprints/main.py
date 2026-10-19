from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from extensions import get_db_connection, log_action, cipher_suite

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return redirect(url_for('auth.login'))

@main.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Stats
    cursor.execute("SELECT COUNT(*) FROM patients")
    total_patients = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM appointments")
    total_appointments = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'doctor' AND is_active = TRUE")
    total_doctors = cursor.fetchone()[0]

    # Today's Appointments
    today = datetime.now().strftime('%Y-%m-%d')
    # PostgreSQL date casting might be needed, but usually string comparison works for dates
    cursor.execute("SELECT COUNT(*) FROM appointments WHERE DATE(appointment_date) = %s", (today,))
    todays_appts = cursor.fetchone()[0]
    
    # Fetch 5 recent patients for the dashboard table
    cursor.execute("SELECT patient_id, full_name, date_of_birth, gender, contact_number FROM patients ORDER BY created_at DESC LIMIT 5")
    raw_patients = cursor.fetchall()
    
    recent_patients = []
    for p in raw_patients:
        try:
            decrypted_contact = cipher_suite.decrypt(p[4].encode()).decode()
        except Exception:
            decrypted_contact = p[4]
        recent_patients.append((p[0], p[1], p[2], p[3], decrypted_contact))
    
    # Data for Charts
    # 1. Gender Distribution
    cursor.execute("SELECT gender, COUNT(*) FROM patients GROUP BY gender")
    gender_data = cursor.fetchall()
    
    # 2. Appointment Status
    cursor.execute("SELECT status, COUNT(*) FROM appointments GROUP BY status")
    appt_data = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('dashboard.html', 
                           username=session['username'], 
                           role=session['role'],
                           total_patients=total_patients,
                           total_appointments=total_appointments,
                           total_doctors=total_doctors,
                           todays_appts=todays_appts,
                           recent_patients=recent_patients,
                           gender_data=gender_data,
                           appt_data=appt_data)