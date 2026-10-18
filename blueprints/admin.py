from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file
import os
import subprocess
from datetime import datetime
from extensions import get_db_connection, log_action, db_config

admin = Blueprint('admin', __name__)

@admin.route('/manage_users')
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

@admin.route('/toggle_user/<int:user_id>')
def toggle_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    if user_id == session['user_id']:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for('admin.manage_users'))
    
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
    return redirect(url_for('admin.manage_users'))

@admin.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    if user_id == session['user_id']:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('admin.manage_users'))
    
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
    return redirect(url_for('admin.manage_users'))

@admin.route('/deleted_users')
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

@admin.route('/audit_logs')
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

@admin.route('/backup')
def backup_page():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied: Only Admins can access backups.", 403
    return render_template('backup.html')

@admin.route('/download_backup')
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
        return redirect(url_for('admin.backup_page'))

@admin.route('/restore_backup', methods=['POST'])
def restore_backup():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    if 'backup_file' not in request.files:
        flash("No file uploaded.", "error")
        return redirect(url_for('admin.backup_page'))
        
    file = request.files['backup_file']
    if file.filename == '':
        flash("No file selected.", "error")
        return redirect(url_for('admin.backup_page'))
        
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
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            flash(f"Restore Failed: {e}", "error")
            return redirect(url_for('admin.backup_page'))
    else:
        flash("Invalid file format. Please upload a .sql file.", "error")
        return redirect(url_for('admin.backup_page'))