from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from extensions import get_db_connection, log_action

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
    
    return render_template('manage_users.html', 
                           users=users, 
                           username=session['username'], 
                           role=session['role'])

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
    
    return render_template('deleted_users.html', 
                           deleted=deleted, 
                           username=session['username'], 
                           role=session['role'])

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
    
    return render_template('audit_logs.html', 
                           logs=logs, 
                           username=session['username'], 
                           role=session['role'])

@admin.route('/backup')
def backup_page():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied: Only Admins can access backups.", 403
    return render_template('backup.html', 
                           username=session['username'], 
                           role=session['role'])