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

@main.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
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
        return redirect(url_for('main.view_patients'))

    return render_template('add_patient.html')

@main.route('/view_patients')
def view_patients():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    search_query = request.args.get('search', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if search_query:
        cursor.execute("SELECT patient_id, full_name, date_of_birth, gender, contact_number, created_at FROM patients WHERE full_name LIKE %s ORDER BY created_at DESC", ('%' + search_query + '%',))
    else:
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
    
    return render_template('view_patients.html', patients=patients, search_query=search_query)

@main.route('/schedule_appointment', methods=['GET', 'POST'])
def schedule_appointment():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
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
        return redirect(url_for('main.view_appointments'))

    cursor.execute("SELECT patient_id, full_name FROM patients ORDER BY full_name")
    patients = cursor.fetchall()
    
    cursor.execute("SELECT user_id, full_name FROM users WHERE role = 'doctor' ORDER BY full_name")
    doctors = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('schedule_appointment.html', patients=patients, doctors=doctors)

@main.route('/view_appointments')
def view_appointments():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
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

@main.route('/update_appointment/<int:appt_id>/<string:new_status>')
def update_appointment(appt_id, new_status):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    if session.get('role') not in ['doctor', 'admin']:
        flash("Access Denied: Only Doctors and Admins can update appointment status.", "error")
        return redirect(url_for('main.view_appointments'))
        
    if new_status not in ['completed', 'cancelled', 'scheduled']:
        flash("Invalid status.", "error")
        return redirect(url_for('main.view_appointments'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if session.get('role') == 'doctor':
        cursor.execute("SELECT doctor_id FROM appointments WHERE appointment_id = %s", (appt_id,))
        appt = cursor.fetchone()
        if not appt or appt[0] != session['user_id']:
            flash("Access Denied: You can only update your own appointments.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('main.view_appointments'))

    cursor.execute("UPDATE appointments SET status = %s WHERE appointment_id = %s", (new_status, appt_id))
    conn.commit()
    
    log_action(session['user_id'], "APPOINTMENT_STATUS_UPDATED", f"Appointment {appt_id} marked as {new_status}", request.remote_addr)
    flash(f"Appointment marked as {new_status}!", "success")
    
    cursor.close()
    conn.close()
    return redirect(url_for('main.view_appointments'))